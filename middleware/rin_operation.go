package middleware

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const rinOperationHeader = "X-Rinspace-Operation-Key"
const rinOperationStatusHeader = "X-Rinspace-Operation-Status"
const rinReceiptLimit = 1 << 20

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
		var request struct {
			Model       string  `json:"model"`
			Stream      bool    `json:"stream"`
			MaxTokens   int     `json:"max_tokens"`
			Temperature float64 `json:"temperature"`
			Thinking    struct {
				Type string `json:"type"`
			} `json:"thinking"`
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		var fields map[string]any
		if err := common.Unmarshal(body, &request); err != nil || common.Unmarshal(body, &fields) != nil ||
			len(fields) != 6 || request.Model != "deepseek-flash" || request.Stream ||
			request.MaxTokens < 1 || request.MaxTokens > 4096 ||
			request.Temperature < 0 || request.Temperature > 2 ||
			request.Thinking.Type != "disabled" || len(request.Messages) < 2 || len(request.Messages) > 16 {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "rin chat request is invalid"})
			return
		}
		_, validModel := fields["model"].(string)
		_, validStream := fields["stream"].(bool)
		_, validMaxTokens := fields["max_tokens"].(float64)
		_, validTemperature := fields["temperature"].(float64)
		if !validModel || !validStream || !validMaxTokens || !validTemperature {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "rin chat request is invalid"})
			return
		}
		for name := range fields {
			switch name {
			case "model", "messages", "stream", "max_tokens", "temperature", "thinking":
			default:
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "rin chat request is invalid"})
				return
			}
		}
		thinking, validThinking := fields["thinking"].(map[string]any)
		rawMessages, validMessages := fields["messages"].([]any)
		if !validThinking || len(thinking) != 1 || thinking["type"] != "disabled" ||
			!validMessages || len(rawMessages) != len(request.Messages) {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "rin chat request is invalid"})
			return
		}
		for i, message := range request.Messages {
			originalMessage, valid := rawMessages[i].(map[string]any)
			if !valid || len(originalMessage) != 2 ||
				originalMessage["role"] != message.Role || originalMessage["content"] != message.Content {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "rin chat request is invalid"})
				return
			}
			if (message.Role != "system" && message.Role != "user" && message.Role != "assistant") ||
				strings.TrimSpace(message.Content) == "" {
				c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "rin chat request is invalid"})
				return
			}
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
