/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

// Package typesafejevmcptoolguardrail screens MCP tools/call requests using TypeSafe
// AI's Jev "System One" model (https://typesafe.ai). Before a tool call reaches the
// MCP server, the tool name and its arguments are sent to Jev as a JSON state along
// with a configurable battery of typed questions (Noul, Score, Choice). The call is
// blocked with a JSON-RPC error when any question's answer crosses its threshold —
// or, in monitor mode, only recorded.
//
// The default battery asks whether the call is destructive, irreversible, or sends
// private data out, plus whether it falls outside the operator's configured scope
// when one is set. The MCP proxy never sees the agent's conversation, so scope is
// judged against that configured text only.
package typesafejevmcptoolguardrail

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	guardrailName  = "TypesafeJevMcpToolGuardrail"
	defaultBaseURL = "https://api.typesafe.ai"
	defaultModel   = "jev-latest"
	defaultTimeout = 5 * time.Second
	maxTimeout     = 30 * time.Second

	mcpPathSegment   = "/mcp"
	mcpSessionHeader = "mcp-session-id"
	methodToolsCall  = "tools/call"

	// A blocked call gets the same status and JSON-RPC code as a call mcp-acl-list
	// denies. A check that could not run (fail closed) is an internal error.
	statusBlocked          = http.StatusBadRequest
	statusCheckUnavailable = http.StatusServiceUnavailable
	jsonRpcErrCodeBlocked  = -32000
	jsonRpcErrCodeInternal = -32603
	jsonRpcErrCodeParse    = -32700
	jsonRpcErrCodeRequest  = -32600
	jsonRpcErrCodeParams   = -32602

	questionTypeNoul   = "noul"
	questionTypeScore  = "score"
	questionTypeChoice = "choice"

	// Jev's documented limits on criteria size per question type.
	maxScoreLevels  = 10
	maxChoiceOption = 255

	modeEnforce = "enforce"
	modeMonitor = "monitor"

	// Jev returns 429 when rate limited and 529 when overloaded; both are
	// documented as retryable. One retry with a short backoff, bounded by the
	// same per-call timeout as the first attempt.
	statusJevOverloaded = 529
	retryBackoff        = 250 * time.Millisecond

	defaultThreshold = 0.7

	// SharedContext.Metadata keys, read by later policies and the traffic-logging
	// analytics publisher.
	metaKeyAssessments   = "typesafe-jev-mcp-tool-guardrail:assessments"
	metaKeyUsage         = "typesafe-jev-mcp-tool-guardrail:usage"
	metaKeyLowConfidence = "typesafe-jev-mcp-tool-guardrail:low-confidence"
)

// guardrailQuestion is one entry in a configured question battery. Criteria
// applies to (and is required for) Score and Choice questions; BlockOn only
// applies to Choice. Threshold is compared against the Noul probability, the
// Score value, or the summed probability of the BlockOn options, depending
// on the question's type. ConfidenceThreshold only applies to Score: a score
// at or above Threshold blocks only when Jev's confidence also reaches it
// (0 means off).
type guardrailQuestion struct {
	Key                 string
	Type                string
	Instructions        string
	Criteria            []string
	BlockOn             []string
	Threshold           float64
	ConfidenceThreshold float64
}

// defaultQuestions is the battery used when "questions" isn't configured. The
// wording was tuned against jev-1.13.0 on hand-labelled tool calls; the
// out-of-scope question is only asked when a scope is configured, since without
// one it has nothing to compare against.
func defaultQuestions(hasScope bool) []guardrailQuestion {
	questions := []guardrailQuestion{
		{
			Key:          "destructive",
			Type:         questionTypeNoul,
			Instructions: "Would running the tool call in `tool` destroy or damage data, files, or systems?",
			Threshold:    defaultThreshold,
		},
		{
			Key:          "irreversible",
			Type:         questionTypeNoul,
			Instructions: "Would running the tool call in `tool` have an effect that cannot be undone, such as sending a message, moving money, or publishing something?",
			Threshold:    defaultThreshold,
		},
		{
			Key:          "exfiltration",
			Type:         questionTypeNoul,
			Instructions: "Would running the tool call in `tool` send secrets, credentials, or private data outside the organisation?",
			Threshold:    defaultThreshold,
		},
	}
	if hasScope {
		questions = append(questions, guardrailQuestion{
			Key:          "out_of_scope",
			Type:         questionTypeNoul,
			Instructions: "Is the tool call in `tool` unrelated to the purpose described in `scope`?",
			Threshold:    defaultThreshold,
		})
	}
	return questions
}

// TypesafeJevMcpToolGuardrailPolicy implements a Jev-backed guardrail for MCP tool calls.
type TypesafeJevMcpToolGuardrailPolicy struct {
	apiKey  string
	baseURL string
	model   string
	client  *http.Client

	scope              string
	questions          []guardrailQuestion
	mode               string
	timeout            time.Duration
	passthroughOnError bool
	showAssessment     bool
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	apiKey, err := requiredStringParam(params, "apiKey")
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	// No client-level timeout: each Jev call is bounded by the configured
	// timeout via context instead.
	p := &TypesafeJevMcpToolGuardrailPolicy{
		apiKey:  apiKey,
		baseURL: stringParamOrDefault(params, "baseURL", defaultBaseURL),
		model:   stringParamOrDefault(params, "model", defaultModel),
		client:  &http.Client{},
		mode:    modeEnforce,
		timeout: defaultTimeout,
	}
	if err := p.parseParams(params); err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}

	slog.Debug("TypesafeJevMcpToolGuardrail: Policy initialized",
		"questions", len(p.questions), "hasScope", p.scope != "", "mode", p.mode)

	return p, nil
}

// Mode buffers the request body only: the tool name and arguments are read from
// the JSON-RPC body, and the response is never inspected.
func (p *TypesafeJevMcpToolGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// OnRequestBody screens a tools/call request. Everything else on the proxy —
// other methods, other routes, JSON-RPC responses and notifications — passes
// through untouched.
func (p *TypesafeJevMcpToolGuardrailPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	// Read the path and headers from the downstream snapshot, so the check and its
	// error responses reflect what the client sent, not what a peer policy rewrote.
	ds := reqCtx.DownstreamRequest()
	routePath := ds.Path
	if reqCtx.SharedContext != nil && reqCtx.OperationPath != "" {
		routePath = reqCtx.OperationPath
	}
	if !isMcpPostRequest(ds.Method, routePath) {
		return policy.UpstreamRequestModifications{}
	}
	if reqCtx.Body == nil || len(reqCtx.Body.Content) == 0 {
		return policy.UpstreamRequestModifications{}
	}

	call, errResp := parseToolCall(reqCtx.Body.Content, ds.Headers)
	if errResp != nil {
		return *errResp
	}
	if call == nil {
		return policy.UpstreamRequestModifications{}
	}
	return p.screen(ctx, reqCtx.SharedContext, ds.Headers, call)
}

// toolCallRequest is the part of a tools/call request that is screened.
type toolCallRequest struct {
	ID        json.RawMessage
	Name      string
	Arguments json.RawMessage
}

// toolCallState is the JSON state sent to Jev. Question instructions refer to
// its fields by name (`tool`, `tool.arguments`, `scope`).
type toolCallState struct {
	Tool  toolCallStateTool `json:"tool"`
	Scope string            `json:"scope,omitempty"`
}

type toolCallStateTool struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// parseToolCall reads a JSON-RPC request body. It returns nil and no error for a
// message that isn't a tools/call, and an error response for a body that can't be
// read unambiguously: this policy must screen exactly the call the MCP server will
// run, so a body the server might read differently is refused rather than passed.
func parseToolCall(body []byte, headers *policy.Headers) (*toolCallRequest, *policy.ImmediateResponse) {
	reject := func(code int, message string, id json.RawMessage) (*toolCallRequest, *policy.ImmediateResponse) {
		resp := buildRequestErrorResponse(headers, statusBlocked, code, message, id, nil)
		return nil, &resp
	}

	raw := body
	if isEventStream(headers) {
		data, ok := firstEventData(body)
		if !ok {
			return reject(jsonRpcErrCodeParse, "Invalid JSON", nil)
		}
		raw = data
	}
	if !json.Valid(raw) {
		return reject(jsonRpcErrCodeParse, "Invalid JSON", nil)
	}
	if !isJSONObject(raw) {
		return reject(jsonRpcErrCodeRequest, "Request body is not a single JSON-RPC request object", nil)
	}

	members, err := objectMembers(raw)
	if err != nil {
		return reject(jsonRpcErrCodeParse, "Invalid JSON", nil)
	}
	if err := checkMemberSpelling(members, "id", "method", "params"); err != nil {
		return reject(jsonRpcErrCodeRequest, "Ambiguous MCP request: "+err.Error(), nil)
	}
	id := memberValue(members, "id")

	methodRaw := memberValue(members, "method")
	if methodRaw == nil {
		// A JSON-RPC response or a malformed message; nothing to screen.
		return nil, nil
	}
	var method string
	if err := json.Unmarshal(methodRaw, &method); err != nil {
		return reject(jsonRpcErrCodeRequest, "Request body has a member of the wrong type", id)
	}
	if method != methodToolsCall {
		return nil, nil
	}

	paramsRaw := memberValue(members, "params")
	if paramsRaw == nil || !isJSONObject(paramsRaw) {
		return reject(jsonRpcErrCodeParams, "Invalid MCP request params", id)
	}
	params, err := objectMembers(paramsRaw)
	if err != nil {
		return reject(jsonRpcErrCodeParams, "Invalid MCP request params", id)
	}
	if err := checkMemberSpelling(params, "name", "arguments"); err != nil {
		return reject(jsonRpcErrCodeRequest, "Ambiguous MCP request: "+err.Error(), id)
	}

	var name string
	if nameRaw := memberValue(params, "name"); nameRaw != nil {
		if err := json.Unmarshal(nameRaw, &name); err != nil {
			return reject(jsonRpcErrCodeParams, "Invalid MCP request params", id)
		}
	}
	if strings.TrimSpace(name) == "" {
		return reject(jsonRpcErrCodeParams, "Missing MCP tool name", id)
	}

	arguments := memberValue(params, "arguments")
	if arguments != nil && !isJSONObject(arguments) && !bytes.Equal(bytes.TrimSpace(arguments), []byte("null")) {
		return reject(jsonRpcErrCodeParams, "Invalid MCP request params", id)
	}

	return &toolCallRequest{ID: id, Name: name, Arguments: arguments}, nil
}

// screen asks Jev the configured questions about one tool call and returns either
// a passthrough or a blocking JSON-RPC error.
func (p *TypesafeJevMcpToolGuardrailPolicy) screen(ctx context.Context, shared *policy.SharedContext, headers *policy.Headers, call *toolCallRequest) policy.RequestAction {
	// failure handles an error in the check itself (not a violation). Monitor mode
	// never blocks, so it always passes through regardless of passthroughOnError.
	failure := func(reason string, err error) policy.RequestAction {
		if p.mode == modeMonitor || p.passthroughOnError {
			slog.Debug("TypesafeJevMcpToolGuardrail: check failed, passing through",
				"reason", reason, "error", err, "mode", p.mode, "tool", call.Name)
			return policy.UpstreamRequestModifications{}
		}
		slog.Debug("TypesafeJevMcpToolGuardrail: check failed, failing closed",
			"reason", reason, "error", err, "tool", call.Name)
		return buildRequestErrorResponse(headers, statusCheckUnavailable, jsonRpcErrCodeInternal,
			"MCP tool call could not be checked by guardrail", call.ID, nil)
	}

	state := toolCallState{
		Tool:  toolCallStateTool{Name: call.Name, Arguments: call.Arguments},
		Scope: p.scope,
	}
	answers, usage, err := p.callJev(ctx, state, p.questions, p.timeout)
	if err != nil {
		return failure("Error calling Jev API", err)
	}
	if usage != nil {
		setMetadata(shared, metaKeyUsage, map[string]interface{}{
			"input_tokens": usage.InputTokens, "output_tokens": usage.OutputTokens,
		})
	}

	var failed, lowConfidence []map[string]interface{}
	for _, q := range p.questions {
		raw, ok := answers[q.Key]
		if !ok {
			// A partial Jev response is a failure of the check, not a pass: a
			// fail-closed operator's call must not go through on a missing answer.
			return failure("Error processing Jev response", fmt.Errorf("Jev response missing answer for question %q", q.Key))
		}
		assessment, blocks, err := evaluateAnswer(q, raw)
		if err != nil {
			return failure("Error processing Jev response", fmt.Errorf("question %q: %w", q.Key, err))
		}
		switch {
		case blocks:
			failed = append(failed, assessment)
		case assessment != nil:
			lowConfidence = append(lowConfidence, assessment)
		}
	}

	if len(lowConfidence) > 0 {
		setMetadata(shared, metaKeyLowConfidence, lowConfidence)
		slog.Debug("TypesafeJevMcpToolGuardrail: threshold reached below confidenceThreshold, not blocking",
			"questions", lowConfidence, "tool", call.Name)
	}

	if len(failed) == 0 {
		return policy.UpstreamRequestModifications{}
	}

	setMetadata(shared, metaKeyAssessments, failed)

	if p.mode == modeMonitor {
		slog.Info("TypesafeJevMcpToolGuardrail: violation detected (monitor mode, not blocking)",
			"failedQuestions", failed, "tool", call.Name)
		return policy.UpstreamRequestModifications{AnalyticsMetadata: guardrailHitAnalytics()}
	}

	slog.Debug("TypesafeJevMcpToolGuardrail: violation detected", "failedQuestions", failed, "tool", call.Name)
	var data map[string]interface{}
	if p.showAssessment {
		data = map[string]interface{}{
			"interveningGuardrail": guardrailName,
			"assessments":          failed,
		}
	}
	resp := buildRequestErrorResponse(headers, statusBlocked, jsonRpcErrCodeBlocked,
		"MCP tool call blocked by guardrail", call.ID, data)
	for k, v := range guardrailHitAnalytics() {
		resp.AnalyticsMetadata[k] = v
	}
	return resp
}

func guardrailHitAnalytics() map[string]interface{} {
	return map[string]interface{}{
		"isGuardrailHit": true,
		"guardrailName":  guardrailName,
	}
}

// evaluateAnswer decodes one question's answer and returns its assessment
// entry when the answer is at or above the question's threshold, or nil when
// it isn't. blocks is false for a score that reached its threshold without
// reaching its confidenceThreshold: that assessment is only recorded.
func evaluateAnswer(q guardrailQuestion, raw json.RawMessage) (assessment map[string]interface{}, blocks bool, err error) {
	assessment = map[string]interface{}{
		"question": q.Key, "type": q.Type, "threshold": q.Threshold,
	}
	var value float64
	var confidence *float64
	switch q.Type {
	case questionTypeNoul:
		v, err := decodeNoulAnswer(raw)
		if err != nil {
			return nil, false, err
		}
		value = v
	case questionTypeScore:
		a, err := decodeScoreAnswer(raw)
		if err != nil {
			return nil, false, err
		}
		value = a.Score
		confidence = a.Confidence
		if a.Confidence != nil {
			assessment["confidence"] = *a.Confidence
		}
		// Jev always reports a Score's confidence; a missing one can't be
		// checked against the configured threshold, so it's a malformed answer.
		if q.ConfidenceThreshold > 0 && a.Confidence == nil {
			return nil, false, fmt.Errorf("answer missing 'confidence' field")
		}
	case questionTypeChoice:
		a, err := decodeChoiceAnswer(raw)
		if err != nil {
			return nil, false, err
		}
		// The blocking value is the total probability mass on the BlockOn
		// options, not just whether one of them won the argmax.
		for _, option := range q.BlockOn {
			value += a.Probabilities[option]
		}
		assessment["choice"] = a.Choice
		if a.Confidence != nil {
			assessment["confidence"] = *a.Confidence
		}
	default:
		return nil, false, fmt.Errorf("unsupported question type %q", q.Type)
	}
	if value < q.Threshold {
		return nil, false, nil
	}
	assessment["value"] = value
	if q.ConfidenceThreshold > 0 && *confidence < q.ConfidenceThreshold {
		assessment["confidenceThreshold"] = q.ConfidenceThreshold
		return assessment, false, nil
	}
	return assessment, true, nil
}

// setMetadata records a value in SharedContext.Metadata, where later
// policies and the traffic-logging analytics publisher can read it.
func setMetadata(shared *policy.SharedContext, key string, value interface{}) {
	if shared == nil {
		return
	}
	if shared.Metadata == nil {
		shared.Metadata = make(map[string]interface{})
	}
	shared.Metadata[key] = value
}

// --- MCP request handling ---

// isMcpPostRequest reports whether the request targets the MCP endpoint.
func isMcpPostRequest(method, path string) bool {
	if !strings.EqualFold(method, http.MethodPost) {
		return false
	}
	cleanPath := strings.TrimSpace(path)
	if idx := strings.Index(cleanPath, "?"); idx >= 0 {
		cleanPath = cleanPath[:idx]
	}
	return cleanPath == mcpPathSegment || strings.HasPrefix(cleanPath, mcpPathSegment+"/")
}

// getSessionID extracts the MCP session ID from v1alpha2 headers.
func getSessionID(headers *policy.Headers) string {
	if headers == nil {
		return ""
	}
	for key, values := range headers.GetAll() {
		if strings.ToLower(key) == mcpSessionHeader {
			if len(values) > 0 {
				return values[0]
			}
		}
	}
	return ""
}

// isEventStream reports whether v1alpha2 headers indicate an SSE payload.
func isEventStream(headers *policy.Headers) bool {
	if headers == nil {
		return false
	}
	for key, values := range headers.GetAll() {
		if strings.ToLower(key) == "content-type" {
			for _, value := range values {
				if strings.Contains(strings.ToLower(value), "text/event-stream") {
					return true
				}
			}
		}
	}
	return false
}

// firstEventData returns the data of the first SSE event that carries any,
// joining multi-line data the way the SSE format defines.
func firstEventData(body []byte) ([]byte, bool) {
	var dataLines []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			if len(dataLines) > 0 {
				break
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			dataLines = append(dataLines, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	data := strings.Join(dataLines, "\n")
	if strings.TrimSpace(data) == "" {
		return nil, false
	}
	return []byte(data), true
}

// buildRequestErrorResponse builds a JSON-RPC error response, framed as SSE when
// the request was, and echoing the request id and MCP session id.
func buildRequestErrorResponse(headers *policy.Headers, statusCode int, jsonRpcCode int, message string, requestID json.RawMessage, data map[string]interface{}) policy.ImmediateResponse {
	errObj := map[string]interface{}{
		"code":    jsonRpcCode,
		"message": message,
	}
	if data != nil {
		errObj["data"] = data
	}
	id := requestID
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	body, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   errObj,
	})
	if err != nil {
		slog.Debug("TypesafeJevMcpToolGuardrail: Failed to marshal error response", "error", err)
		body = fmt.Appendf(nil, `{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":"Unexpected error"}}`, string(id), jsonRpcErrCodeInternal)
	}

	respHeaders := map[string]string{"Content-Type": "application/json"}
	if isEventStream(headers) {
		respHeaders["Content-Type"] = "text/event-stream"
		body = []byte("data: " + string(body) + "\n\n")
	}
	if sessionID := getSessionID(headers); sessionID != "" {
		respHeaders[mcpSessionHeader] = sessionID
	}

	return policy.ImmediateResponse{
		StatusCode:        statusCode,
		Headers:           respHeaders,
		Body:              body,
		AnalyticsMetadata: map[string]interface{}{"mcpErrorCode": jsonRpcCode},
	}
}

// jsonMember is a single object member, kept in document order so that duplicate
// names remain visible.
type jsonMember struct {
	name  string
	value json.RawMessage
}

// objectMembers returns the members of a JSON object in document order,
// including any repeated names.
func objectMembers(raw []byte) ([]jsonMember, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return nil, errors.New("expected a JSON object")
	}

	var members []jsonMember
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		name, ok := tok.(string)
		if !ok {
			return nil, errors.New("expected a JSON object member name")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		members = append(members, jsonMember{name: name, value: value})
	}
	return members, nil
}

// checkMemberSpelling rejects an object in which a member the policy reads is
// present more than once or under a non-canonical spelling, since the MCP server
// might resolve it to a different value than this policy screens.
func checkMemberSpelling(members []jsonMember, canonicalNames ...string) error {
	seen := make(map[string]string, len(canonicalNames))
	for _, member := range members {
		canonicalName := ""
		for _, name := range canonicalNames {
			if strings.EqualFold(member.name, name) {
				canonicalName = name
				break
			}
		}
		if canonicalName == "" {
			continue
		}
		if previous, duplicate := seen[canonicalName]; duplicate {
			return fmt.Errorf("members %q and %q both resolve to %q", previous, member.name, canonicalName)
		}
		if member.name != canonicalName {
			return fmt.Errorf("member %q must be spelled %q", member.name, canonicalName)
		}
		seen[canonicalName] = member.name
	}
	return nil
}

// memberValue returns the value of the named member, or nil when it is absent.
// Call it only after checkMemberSpelling has ruled out duplicates.
func memberValue(members []jsonMember, name string) json.RawMessage {
	for _, member := range members {
		if member.name == name {
			return member.value
		}
	}
	return nil
}

func isJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	return len(trimmed) > 0 && trimmed[0] == '{'
}

// --- Jev API client ---

type jevQuestionPayload struct {
	Type         string      `json:"type"`
	Instructions string      `json:"instructions"`
	Criteria     interface{} `json:"criteria,omitempty"`
}

type jevSystemOneRequest struct {
	State     toolCallState                 `json:"state"`
	Model     string                        `json:"model"`
	Questions map[string]jevQuestionPayload `json:"questions"`
}

type jevUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type jevSystemOneResponse struct {
	Answers map[string]json.RawMessage `json:"answers"`
	Usage   *jevUsage                  `json:"usage"`
}

func (p *TypesafeJevMcpToolGuardrailPolicy) callJev(ctx context.Context, state toolCallState, questions []guardrailQuestion, timeout time.Duration) (map[string]json.RawMessage, *jevUsage, error) {
	questionMap := make(map[string]jevQuestionPayload, len(questions))
	for _, q := range questions {
		payload := jevQuestionPayload{Type: q.Type, Instructions: q.Instructions}
		switch q.Type {
		case questionTypeScore:
			payload.Criteria = q.Criteria
		case questionTypeChoice:
			// Jev's Choice criteria is a map of option id -> description; a
			// null description means the id itself is the description.
			options := make(map[string]*string, len(q.Criteria))
			for _, option := range q.Criteria {
				options[option] = nil
			}
			payload.Criteria = options
		}
		questionMap[q.Key] = payload
	}

	reqBody := jevSystemOneRequest{State: state, Model: p.model, Questions: questionMap}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal Jev request: %w", err)
	}

	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	status, body, err := p.postSystemOne(ctx, payload)
	if err == nil && (status == http.StatusTooManyRequests || status == statusJevOverloaded) {
		slog.Debug("TypesafeJevMcpToolGuardrail: Jev rate limited or overloaded, retrying once", "status", status)
		select {
		case <-ctx.Done():
			return nil, nil, fmt.Errorf("Jev API returned status %d and timed out before retry: %w", status, ctx.Err())
		case <-time.After(retryBackoff):
		}
		status, body, err = p.postSystemOne(ctx, payload)
	}
	if err != nil {
		return nil, nil, err
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("Jev API returned status %d: %s", status, string(body))
	}

	var parsed jevSystemOneResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, nil, fmt.Errorf("failed to decode Jev response: %w", err)
	}
	return parsed.Answers, parsed.Usage, nil
}

func (p *TypesafeJevMcpToolGuardrailPolicy) postSystemOne(ctx context.Context, payload []byte) (int, []byte, error) {
	url := strings.TrimSuffix(p.baseURL, "/") + "/v1/systemone"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create Jev HTTP request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return 0, nil, fmt.Errorf("Jev HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read Jev response: %w", err)
	}
	return resp.StatusCode, body, nil
}

// decodeNoulAnswer requires the "noul" field to actually be present: a
// pointer field distinguishes "absent" from "present and 0", since a
// malformed Jev response missing this field must not silently decode as a
// confident non-violation.
func decodeNoulAnswer(raw json.RawMessage) (float64, error) {
	var a struct {
		Noul *float64 `json:"noul"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return 0, err
	}
	if a.Noul == nil {
		return 0, fmt.Errorf("answer missing 'noul' field")
	}
	return *a.Noul, nil
}

type scoreAnswer struct {
	Score      float64
	Confidence *float64
}

// decodeScoreAnswer mirrors decodeNoulAnswer's absent-field handling for the
// "score" field. Confidence is optional and only reported, never required.
func decodeScoreAnswer(raw json.RawMessage) (scoreAnswer, error) {
	var a struct {
		Score      *float64 `json:"score"`
		Confidence *float64 `json:"confidence"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return scoreAnswer{}, err
	}
	if a.Score == nil {
		return scoreAnswer{}, fmt.Errorf("answer missing 'score' field")
	}
	return scoreAnswer{Score: *a.Score, Confidence: a.Confidence}, nil
}

type choiceAnswer struct {
	Choice        string
	Probabilities map[string]float64
	Confidence    *float64
}

// decodeChoiceAnswer requires "probabilities" to be present, since the
// blocking value is computed from it; a missing distribution must not
// decode as zero probability on every blocked option.
func decodeChoiceAnswer(raw json.RawMessage) (choiceAnswer, error) {
	var a struct {
		Choice        string             `json:"choice"`
		Probabilities map[string]float64 `json:"probabilities"`
		Confidence    *float64           `json:"confidence"`
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		return choiceAnswer{}, err
	}
	if a.Probabilities == nil {
		return choiceAnswer{}, fmt.Errorf("answer missing 'probabilities' field")
	}
	return choiceAnswer{Choice: a.Choice, Probabilities: a.Probabilities, Confidence: a.Confidence}, nil
}

// --- Parameter parsing ---

func requiredStringParam(params map[string]interface{}, key string) (string, error) {
	raw, ok := params[key]
	if !ok {
		return "", fmt.Errorf("'%s' parameter is required", key)
	}
	value, ok := raw.(string)
	if !ok || value == "" {
		return "", fmt.Errorf("'%s' must be a non-empty string", key)
	}
	return value, nil
}

func stringParamOrDefault(params map[string]interface{}, key, def string) string {
	if raw, ok := params[key]; ok {
		if value, ok := raw.(string); ok && value != "" {
			return value
		}
	}
	return def
}

func (p *TypesafeJevMcpToolGuardrailPolicy) parseParams(params map[string]interface{}) error {
	if scopeRaw, ok := params["scope"]; ok {
		scope, ok := scopeRaw.(string)
		if !ok {
			return fmt.Errorf("'scope' must be a string")
		}
		p.scope = strings.TrimSpace(scope)
	}

	if modeRaw, ok := params["mode"]; ok {
		mode, ok := modeRaw.(string)
		if !ok || (mode != modeEnforce && mode != modeMonitor) {
			return fmt.Errorf("'mode' must be '%s' or '%s'", modeEnforce, modeMonitor)
		}
		p.mode = mode
	}

	if timeoutRaw, ok := params["timeout"]; ok {
		timeoutStr, ok := timeoutRaw.(string)
		if !ok {
			return fmt.Errorf("'timeout' must be a duration string (e.g. \"5s\")")
		}
		timeout, err := time.ParseDuration(timeoutStr)
		if err != nil {
			return fmt.Errorf("'timeout' is not a valid duration: %w", err)
		}
		if timeout <= 0 || timeout > maxTimeout {
			return fmt.Errorf("'timeout' must be greater than 0 and at most %s", maxTimeout)
		}
		p.timeout = timeout
	}

	if passthroughRaw, ok := params["passthroughOnError"]; ok {
		passthrough, ok := passthroughRaw.(bool)
		if !ok {
			return fmt.Errorf("'passthroughOnError' must be a boolean")
		}
		p.passthroughOnError = passthrough
	}

	if showAssessmentRaw, ok := params["showAssessment"]; ok {
		showAssessment, ok := showAssessmentRaw.(bool)
		if !ok {
			return fmt.Errorf("'showAssessment' must be a boolean")
		}
		p.showAssessment = showAssessment
	}

	questionsRaw, ok := params["questions"]
	if !ok {
		p.questions = defaultQuestions(p.scope != "")
		return nil
	}
	questionsList, ok := questionsRaw.([]interface{})
	if !ok {
		return fmt.Errorf("'questions' must be an array")
	}
	if len(questionsList) == 0 {
		p.questions = defaultQuestions(p.scope != "")
		return nil
	}

	questions := make([]guardrailQuestion, 0, len(questionsList))
	seenKeys := make(map[string]bool, len(questionsList))
	for i, item := range questionsList {
		qMap, ok := item.(map[string]interface{})
		if !ok {
			return fmt.Errorf("'questions[%d]' must be an object", i)
		}
		q, err := parseQuestion(qMap, i)
		if err != nil {
			return err
		}
		if seenKeys[q.Key] {
			return fmt.Errorf("'questions[%d].key' %q is a duplicate; question keys must be unique", i, q.Key)
		}
		seenKeys[q.Key] = true
		questions = append(questions, q)
	}
	p.questions = questions
	return nil
}

func parseQuestion(qMap map[string]interface{}, index int) (guardrailQuestion, error) {
	var q guardrailQuestion

	key, ok := qMap["key"].(string)
	if !ok || key == "" {
		return q, fmt.Errorf("'questions[%d].key' is required and must be a non-empty string", index)
	}
	q.Key = key

	qType, ok := qMap["type"].(string)
	if !ok || (qType != questionTypeNoul && qType != questionTypeScore && qType != questionTypeChoice) {
		return q, fmt.Errorf("'questions[%d].type' is required and must be 'noul', 'score', or 'choice'", index)
	}
	q.Type = qType

	instructions, ok := qMap["instructions"].(string)
	if !ok || instructions == "" {
		return q, fmt.Errorf("'questions[%d].instructions' is required and must be a non-empty string", index)
	}
	q.Instructions = instructions

	threshold, err := extractFloat(qMap["threshold"])
	if err != nil {
		return q, fmt.Errorf("'questions[%d].threshold' must be a number: %w", index, err)
	}
	q.Threshold = threshold

	if raw, ok := qMap["confidenceThreshold"]; ok {
		// Noul answers carry no confidence, and Choice already blocks on the
		// combined probability of its blockOn options.
		if qType != questionTypeScore {
			return q, fmt.Errorf("'questions[%d].confidenceThreshold' only applies to type 'score'", index)
		}
		confidenceThreshold, err := extractFloat(raw)
		if err != nil {
			return q, fmt.Errorf("'questions[%d].confidenceThreshold' must be a number: %w", index, err)
		}
		if confidenceThreshold < 0 || confidenceThreshold > 1 {
			return q, fmt.Errorf("'questions[%d].confidenceThreshold' must be between 0 and 1", index)
		}
		q.ConfidenceThreshold = confidenceThreshold
	}

	switch qType {
	case questionTypeScore:
		criteria, err := parseStringList(qMap["criteria"], fmt.Sprintf("questions[%d].criteria", index))
		if err != nil {
			return q, err
		}
		if len(criteria) < 2 || len(criteria) > maxScoreLevels {
			return q, fmt.Errorf("'questions[%d].criteria' is required for type 'score' and must have 2 to %d entries", index, maxScoreLevels)
		}
		q.Criteria = criteria
	case questionTypeChoice:
		criteria, err := parseStringList(qMap["criteria"], fmt.Sprintf("questions[%d].criteria", index))
		if err != nil {
			return q, err
		}
		if len(criteria) < 2 || len(criteria) > maxChoiceOption {
			return q, fmt.Errorf("'questions[%d].criteria' is required for type 'choice' and must have 2 to %d entries", index, maxChoiceOption)
		}
		options := make(map[string]bool, len(criteria))
		for _, option := range criteria {
			if options[option] {
				return q, fmt.Errorf("'questions[%d].criteria' has duplicate option %q", index, option)
			}
			options[option] = true
		}
		blockOn, err := parseStringList(qMap["blockOn"], fmt.Sprintf("questions[%d].blockOn", index))
		if err != nil {
			return q, err
		}
		if len(blockOn) == 0 {
			return q, fmt.Errorf("'questions[%d].blockOn' is required for type 'choice' and must name at least one option", index)
		}
		for _, option := range blockOn {
			if !options[option] {
				return q, fmt.Errorf("'questions[%d].blockOn' option %q is not in criteria", index, option)
			}
		}
		if threshold <= 0 || threshold > 1 {
			return q, fmt.Errorf("'questions[%d].threshold' for type 'choice' must be a probability in (0, 1]", index)
		}
		q.Criteria = criteria
		q.BlockOn = blockOn
	}

	return q, nil
}

// parseStringList returns nil (not an error) when raw is absent, so callers
// can apply their own "required" check with a type-specific message.
func parseStringList(raw interface{}, field string) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	list, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("'%s' must be an array of strings", field)
	}
	result := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("'%s' entries must be strings", field)
		}
		result = append(result, s)
	}
	return result, nil
}

func extractFloat(value interface{}) (float64, error) {
	switch v := value.(type) {
	case float64:
		return v, nil
	case int:
		return float64(v), nil
	case nil:
		return 0, fmt.Errorf("value is required")
	default:
		return 0, fmt.Errorf("cannot convert %T to number", value)
	}
}
