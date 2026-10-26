package middleware

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const rinOperationHeader = "X-Rinspace-Operation-Key"
const rinOperationStatusHeader = "X-Rinspace-Operation-Status"
const rinReceiptLimit = 1 << 20

const (
	rinAgentMessageLimit = 96
	rinAgentToolLimit    = 32
	rinAgentContentLimit = 64 << 10
)

type rinOperationRequest struct {
	Model       string                `json:"model"`
	Messages    []rinOperationMessage `json:"messages"`
	Tools       []rinOperationTool    `json:"tools"`
	ToolChoice  string                `json:"tool_choice"`
	Stream      bool                  `json:"stream"`
	MaxTokens   int                   `json:"max_tokens"`
	Temperature float64               `json:"temperature"`
	Thinking    struct {
		Type string `json:"type"`
	} `json:"thinking"`
}

type rinOperationMessage struct {
	Role       string                 `json:"role"`
	Content    string                 `json:"content"`
	ToolCallID string                 `json:"tool_call_id"`
	ToolCalls  []rinOperationToolCall `json:"tool_calls"`
}

type rinOperationTool struct {
	Type     string                         `json:"type"`
	Function rinOperationFunctionDefinition `json:"function"`
}

type rinOperationFunctionDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

type rinOperationToolCall struct {
	ID       string                   `json:"id"`
	Type     string                   `json:"type"`
	Function rinOperationFunctionCall `json:"function"`
}

type rinOperationFunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type rinReceiptWriter struct {
	gin.ResponseWriter
	header   http.Header
	body     bytes.Buffer
	status   int
	tooLarge bool
}

func (w *rinReceiptWriter) Header() http.Header  { return w.header }
func (w *rinReceiptWriter) WriteHeader(code int) { w.status = code }
func (w *rinReceiptWriter) WriteHeaderNow() {
	if w.status == 0 {
		w.status = http.StatusOK
	}
}
func (w *rinReceiptWriter) Status() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}
func (w *rinReceiptWriter) Size() int     { return w.body.Len() }
func (w *rinReceiptWriter) Written() bool { return w.status != 0 || w.body.Len() != 0 }

// The relay flushes even complete non-streaming JSON responses. Keep it in the
// receipt buffer until the operation has been committed to the database.
func (w *rinReceiptWriter) Flush() {}
func (w *rinReceiptWriter) Write(p []byte) (int, error) {
	w.WriteHeaderNow()
	if w.body.Len()+len(p) > rinReceiptLimit {
		w.tooLarge = true
		return len(p), nil
	}
	return w.body.Write(p)
}
func (w *rinReceiptWriter) WriteString(s string) (int, error) { return w.Write([]byte(s)) }

func rinReceiptCipher() (cipher.AEAD, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv("RINSPACE_RIN_RECEIPT_KEY")))
	if err != nil || len(key) != 32 {
		return nil, errors.New("rin receipt encryption key is unavailable")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func rinReceiptAAD(operation model.RinOperation) []byte {
	return []byte(fmt.Sprintf("%d:%s:%s", operation.TokenID, operation.OperationKey, operation.RequestHash))
}

func encryptRinReceipt(aead cipher.AEAD, operation model.RinOperation, body []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, body, rinReceiptAAD(operation)), nil
}

func decryptRinReceipt(aead cipher.AEAD, operation model.RinOperation) ([]byte, error) {
	if len(operation.ResponseCiphertext) < aead.NonceSize() {
		return nil, errors.New("rin receipt is missing")
	}
	nonce := operation.ResponseCiphertext[:aead.NonceSize()]
	return aead.Open(nil, nonce, operation.ResponseCiphertext[aead.NonceSize():], rinReceiptAAD(operation))
}

func rinTokenID() int {
	id, err := strconv.Atoi(strings.TrimSpace(os.Getenv("RINSPACE_RIN_TOKEN_ID")))
	if err != nil || id <= 0 {
		return 0
	}
	return id
}

func rinExactFields(fields map[string]any, names ...string) bool {
	if len(fields) != len(names) {
		return false
	}
	for _, name := range names {
		if _, exists := fields[name]; !exists {
			return false
		}
	}
	return true
}

func rinAgentName(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' ||
			char >= '0' && char <= '9' || char == '_' || char == '-') {
			return false
		}
	}
	return true
}

func rinAgentCallID(value string) bool {
	const limit = 128
	if len(value) == 0 || len(value) > limit {
		return false
	}
	for _, char := range value {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' ||
			char >= '0' && char <= '9' || char == '_' || char == '-' || char == '.') {
			return false
		}
	}
	return true
}

func rinJSONObject(raw []byte) bool {
	var value map[string]any
	return len(raw) > 0 && common.Unmarshal(raw, &value) == nil && value != nil
}

func validRinChatRequest(body []byte, fields map[string]any) bool {
	var request rinOperationRequest
	if common.Unmarshal(body, &request) != nil ||
		!rinExactFields(fields, "model", "messages", "stream", "max_tokens", "temperature", "thinking") ||
		request.Model != "deepseek-flash" || request.Stream ||
		request.MaxTokens < 1 || request.MaxTokens > 4096 ||
		request.Temperature < 0 || request.Temperature > 2 ||
		request.Thinking.Type != "disabled" || len(request.Messages) < 2 || len(request.Messages) > 16 {
		return false
	}
	_, validModel := fields["model"].(string)
	_, validStream := fields["stream"].(bool)
	_, validMaxTokens := fields["max_tokens"].(float64)
	_, validTemperature := fields["temperature"].(float64)
	thinking, validThinking := fields["thinking"].(map[string]any)
	rawMessages, validMessages := fields["messages"].([]any)
	if !validModel || !validStream || !validMaxTokens || !validTemperature ||
		!validThinking || !rinExactFields(thinking, "type") || thinking["type"] != "disabled" ||
		!validMessages || len(rawMessages) != len(request.Messages) {
		return false
	}
	for i, message := range request.Messages {
		original, valid := rawMessages[i].(map[string]any)
		if !valid || !rinExactFields(original, "role", "content") ||
			original["role"] != message.Role || original["content"] != message.Content ||
			(message.Role != "system" && message.Role != "user" && message.Role != "assistant") ||
			strings.TrimSpace(message.Content) == "" {
			return false
		}
	}
	return true
}

func validRinAgentRequest(body []byte, fields map[string]any) bool {
	var request rinOperationRequest
	if common.Unmarshal(body, &request) != nil ||
		!rinExactFields(fields, "model", "messages", "tools", "tool_choice", "stream", "max_tokens", "temperature", "thinking") ||
		request.Model != "deepseek-flash" || request.ToolChoice != "auto" || request.Stream ||
		request.MaxTokens < 1 || request.MaxTokens > 4096 ||
		request.Temperature < 0 || request.Temperature > 2 ||
		request.Thinking.Type != "disabled" || len(request.Messages) == 0 || len(request.Messages) > rinAgentMessageLimit ||
		len(request.Tools) == 0 || len(request.Tools) > rinAgentToolLimit {
		return false
	}
	_, validModel := fields["model"].(string)
	_, validToolChoice := fields["tool_choice"].(string)
	_, validStream := fields["stream"].(bool)
	_, validMaxTokens := fields["max_tokens"].(float64)
	_, validTemperature := fields["temperature"].(float64)
	thinking, validThinking := fields["thinking"].(map[string]any)
	rawMessages, validMessages := fields["messages"].([]any)
	rawTools, validTools := fields["tools"].([]any)
	if !validModel || !validToolChoice || !validStream || !validMaxTokens || !validTemperature ||
		!validThinking || !rinExactFields(thinking, "type") || thinking["type"] != "disabled" ||
		!validMessages || len(rawMessages) != len(request.Messages) ||
		!validTools || len(rawTools) != len(request.Tools) {
		return false
	}
	declaredTools := make(map[string]struct{}, len(request.Tools))
	for i, tool := range request.Tools {
		original, valid := rawTools[i].(map[string]any)
		function, validFunction := original["function"].(map[string]any)
		functionName, validName := function["name"].(string)
		description, validDescription := function["description"].(string)
		_, validParameters := function["parameters"].(map[string]any)
		if !valid || !rinExactFields(original, "type", "function") ||
			!validFunction || !rinExactFields(function, "name", "description", "parameters") ||
			!validName || functionName != tool.Function.Name ||
			!validDescription || description != tool.Function.Description || !validParameters ||
			original["type"] != "function" || tool.Type != "function" ||
			!rinAgentName(tool.Function.Name) || len(tool.Function.Description) > 4096 ||
			!utf8.ValidString(tool.Function.Description) || len(tool.Function.Parameters) > rinAgentContentLimit ||
			!rinJSONObject(tool.Function.Parameters) {
			return false
		}
		if _, exists := declaredTools[tool.Function.Name]; exists {
			return false
		}
		declaredTools[tool.Function.Name] = struct{}{}
	}
	pendingCalls := make(map[string]struct{})
	seenCalls := make(map[string]struct{})
	for i, message := range request.Messages {
		original, valid := rawMessages[i].(map[string]any)
		role, validRole := original["role"].(string)
		if !valid || len(message.Content) > rinAgentContentLimit || !utf8.ValidString(message.Content) ||
			!validRole || role != message.Role {
			return false
		}
		switch message.Role {
		case "system", "user":
			content, validContent := original["content"].(string)
			if !rinExactFields(original, "role", "content") || !validContent || content != message.Content ||
				strings.TrimSpace(message.Content) == "" ||
				(message.Role == "system" && i != 0) || (message.Role == "user" && len(pendingCalls) != 0) {
				return false
			}
		case "assistant":
			if len(pendingCalls) != 0 || strings.TrimSpace(message.Content) == "" && len(message.ToolCalls) == 0 ||
				!(rinExactFields(original, "role", "content") || rinExactFields(original, "role", "tool_calls") ||
					rinExactFields(original, "role", "content", "tool_calls")) {
				return false
			}
			if rawContent, hasContent := original["content"]; hasContent {
				content, validContent := rawContent.(string)
				if !validContent || content != message.Content {
					return false
				}
			}
			rawCalls, validCalls := original["tool_calls"].([]any)
			if _, hasCalls := original["tool_calls"]; hasCalls &&
				(!validCalls || len(rawCalls) == 0 || len(rawCalls) != len(message.ToolCalls) || len(rawCalls) > rinAgentToolLimit) {
				return false
			}
			for callIndex, call := range message.ToolCalls {
				rawCall, validCall := rawCalls[callIndex].(map[string]any)
				rawFunction, validFunction := rawCall["function"].(map[string]any)
				var arguments map[string]any
				if !validCall || !rinExactFields(rawCall, "id", "type", "function") ||
					!validFunction || !rinExactFields(rawFunction, "name", "arguments") ||
					call.Type != "function" || !rinAgentCallID(call.ID) ||
					!rinAgentName(call.Function.Name) || len(call.Function.Arguments) == 0 ||
					len(call.Function.Arguments) > rinAgentContentLimit ||
					common.Unmarshal([]byte(call.Function.Arguments), &arguments) != nil || arguments == nil {
					return false
				}
				if _, declared := declaredTools[call.Function.Name]; !declared {
					return false
				}
				if _, seen := seenCalls[call.ID]; seen {
					return false
				}
				seenCalls[call.ID] = struct{}{}
				pendingCalls[call.ID] = struct{}{}
			}
		case "tool":
			content, validContent := original["content"].(string)
			toolCallID, validToolCallID := original["tool_call_id"].(string)
			if !rinExactFields(original, "role", "content", "tool_call_id") ||
				!validContent || content != message.Content || !validToolCallID || toolCallID != message.ToolCallID ||
				strings.TrimSpace(message.Content) == "" || !rinAgentCallID(message.ToolCallID) {
				return false
			}
			if _, pending := pendingCalls[message.ToolCallID]; !pending {
				return false
			}
			delete(pendingCalls, message.ToolCallID)
		default:
			return false
		}
		if i == 0 && message.Role != "system" {
			return false
		}
	}
	lastRole := request.Messages[len(request.Messages)-1].Role
	return len(pendingCalls) == 0 && (lastRole == "user" || lastRole == "tool")
}

func validRinOperationRequest(body []byte) bool {
	var fields map[string]any
	if common.Unmarshal(body, &fields) != nil || fields == nil {
		return false
	}
	if _, isAgent := fields["tools"]; isAgent {
		return validRinAgentRequest(body, fields)
	}
	return validRinChatRequest(body, fields)
}

// RinTokenScope confines the dedicated service token to the chat call and
// receipt control endpoints, even if its model limits are mis-set.
func rinReceiptControlRoute(method, path string) bool {
	const prefix = "/v1/rin/operations/"
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	key := strings.TrimPrefix(path, prefix)
	if method == http.MethodGet {
		return key != "" && !strings.Contains(key, "/")
	}
	if method == http.MethodPost && strings.HasSuffix(key, "/abort") {
		key = strings.TrimSuffix(key, "/abort")
		return key != "" && !strings.Contains(key, "/")
	}
	return false
}

func rinTokenAllowed(tokenID int, method, path string) bool {
	configured := rinTokenID()
	if configured == 0 || tokenID != configured {
		return true
	}
	return method == http.MethodPost && path == "/v1/chat/completions" ||
		rinReceiptControlRoute(method, path)
}

func RinTokenScope() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !rinTokenAllowed(c.GetInt("token_id"), c.Request.Method, c.Request.URL.Path) {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}

// RinOperationReceipt protects the existing non-streaming chat route for the
// dedicated Rin token. An unknown operation is never automatically retried.
func RinOperationReceipt() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodPost || c.Request.URL.Path != "/v1/chat/completions" {
			c.Next()
			return
		}
		configuredToken := rinTokenID()
		key := strings.TrimSpace(c.GetHeader(rinOperationHeader))
		if configuredToken == 0 && key == "" || configuredToken != c.GetInt("token_id") && key == "" {
			c.Next()
			return
		}
		if configuredToken == 0 || configuredToken != c.GetInt("token_id") {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "rin operation token is not permitted"})
			return
		}
		if len(key) == 0 || len(key) > 128 || strings.ContainsAny(key, "\r\n\x00") {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "rin operation key is invalid"})
			return
		}
		aead, err := rinReceiptCipher()
		if err != nil {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "rin operation receipts are unavailable"})
			return
		}
		body, err := io.ReadAll(io.LimitReader(c.Request.Body, rinReceiptLimit+1))
		if err != nil || len(body) > rinReceiptLimit {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "rin request is too large"})
			return
		}
		if !validRinOperationRequest(body) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "rin chat request is invalid"})
			return
		}
		c.Request.Body = io.NopCloser(bytes.NewReader(body))
		hash := sha256.Sum256(body)
		operation, claimed, err := model.ClaimRinOperation(model.DB, configuredToken, key, hex.EncodeToString(hash[:]))
		if errors.Is(err, model.ErrRinOperationConflict) {
			c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "rin operation key has a different request"})
			return
		}
		if err != nil {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "rin operation ledger is unavailable"})
			return
		}
		if !claimed {
			writeRinOperationReceipt(c, aead, operation)
			c.Abort()
			return
		}

		original := c.Writer
		captured := &rinReceiptWriter{ResponseWriter: original, header: original.Header().Clone()}
		c.Writer = captured
		c.Next()
		c.Writer = original
		if captured.tooLarge || captured.body.Len() == 0 ||
			strings.HasPrefix(strings.ToLower(strings.TrimSpace(captured.header.Get("Content-Type"))), "text/event-stream") {
			c.Data(http.StatusServiceUnavailable, "application/json", []byte(`{"error":"rin operation receipt is unavailable"}`))
			return
		}
		ciphertext, err := encryptRinReceipt(aead, operation, captured.body.Bytes())
		if err != nil {
			c.Data(http.StatusServiceUnavailable, "application/json", []byte(`{"error":"rin operation receipt is unavailable"}`))
			return
		}
		status := model.RinOperationCompleted
		if captured.Status() < 200 || captured.Status() >= 300 {
			status = model.RinOperationFailed
		}
		if err := model.CompleteRinOperation(model.DB, operation.ID, status, captured.Status(), ciphertext); err != nil {
			c.Data(http.StatusServiceUnavailable, "application/json", []byte(`{"error":"rin operation receipt is unavailable"}`))
			return
		}
		for name, values := range captured.header {
			if strings.EqualFold(name, "Content-Length") {
				continue
			}
			original.Header()[name] = values
		}
		original.Header().Set(rinOperationStatusHeader, status)
		c.Data(captured.Status(), captured.header.Get("Content-Type"), captured.body.Bytes())
	}
}

func writeRinOperationReceipt(c *gin.Context, aead cipher.AEAD, operation model.RinOperation) {
	switch operation.Status {
	case model.RinOperationUnknown:
		c.Header(rinOperationStatusHeader, model.RinOperationUnknown)
		c.JSON(http.StatusAccepted, gin.H{"status": "unknown"})
	case model.RinOperationExpired:
		c.Header(rinOperationStatusHeader, model.RinOperationExpired)
		c.JSON(http.StatusGone, gin.H{"status": "expired"})
	case model.RinOperationCompleted, model.RinOperationFailed:
		body, err := decryptRinReceipt(aead, operation)
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "rin operation receipt is unavailable"})
			return
		}
		c.Header(rinOperationStatusHeader, operation.Status)
		c.Data(operation.HTTPStatus, "application/json", body)
	default:
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "rin operation receipt is invalid"})
	}
}

// ReadRinOperationReceipt returns only receipts belonging to the dedicated
// authenticated token. The operation key alone is never an authorization grant.
func ReadRinOperationReceipt() gin.HandlerFunc {
	return func(c *gin.Context) {
		if rinTokenID() == 0 || c.GetInt("token_id") != rinTokenID() {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		key := c.Param("key")
		if len(key) == 0 || len(key) > 128 {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		aead, err := rinReceiptCipher()
		if err != nil {
			c.AbortWithStatus(http.StatusServiceUnavailable)
			return
		}
		var operation model.RinOperation
		if err := model.DB.Where("token_id = ? AND operation_key = ?", c.GetInt("token_id"), key).Take(&operation).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.AbortWithStatus(http.StatusNotFound)
			} else {
				c.AbortWithStatus(http.StatusServiceUnavailable)
			}
			return
		}
		writeRinOperationReceipt(c, aead, operation)
	}
}

// AbortMissingRinOperation never changes a claimed call. A missing key is
// tombstoned before the caller may release its reserved wallet funds.
func AbortMissingRinOperation() gin.HandlerFunc {
	return func(c *gin.Context) {
		if rinTokenID() == 0 || c.GetInt("token_id") != rinTokenID() {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		key := c.Param("key")
		if len(key) == 0 || len(key) > 128 {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		aead, err := rinReceiptCipher()
		if err != nil {
			c.AbortWithStatus(http.StatusServiceUnavailable)
			return
		}
		operation, err := model.AbortUnclaimedRinOperation(model.DB, c.GetInt("token_id"), key)
		if err != nil {
			c.AbortWithStatus(http.StatusServiceUnavailable)
			return
		}
		writeRinOperationReceipt(c, aead, operation)
	}
}

// A model call times out well before an hour. An abandoned unknown operation
// can then release the caller's reserved funds, while its key stays tombstoned.
func ExpireOldRinReceipts() error {
	now := time.Now().UTC()
	return model.ExpireRinOperationReceipts(model.DB, now.Add(-30*24*time.Hour), now.Add(-time.Hour))
}
