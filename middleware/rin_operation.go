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
const rinReceiptLimit = 1 << 20

type rinReceiptWriter struct {
	gin.ResponseWriter
	header   http.Header
	body     bytes.Buffer
	status   int
	tooLarge bool
	flushed  bool
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
func (w *rinReceiptWriter) Flush()        { w.flushed = true }
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

// RinTokenScope confines the dedicated service token to the two endpoints
// needed by the Rin chat integration, even if its model limits are mis-set.
func RinTokenScope() gin.HandlerFunc {
	return func(c *gin.Context) {
		if configured := rinTokenID(); configured != 0 && c.GetInt("token_id") == configured {
			chat := c.Request.Method == http.MethodPost && c.Request.URL.Path == "/v1/chat/completions"
			receipt := c.Request.Method == http.MethodGet && strings.HasPrefix(c.Request.URL.Path, "/v1/rin/operations/")
			if !chat && !receipt {
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
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
			Model     string `json:"model"`
			Stream    bool   `json:"stream"`
			MaxTokens int    `json:"max_tokens"`
		}
		if err := common.Unmarshal(body, &request); err != nil || request.Model != "deepseek-flash" || request.Stream || request.MaxTokens < 1 || request.MaxTokens > 4096 {
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
		if captured.tooLarge || captured.flushed || captured.body.Len() == 0 {
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
		c.Data(captured.Status(), captured.header.Get("Content-Type"), captured.body.Bytes())
	}
}

func writeRinOperationReceipt(c *gin.Context, aead cipher.AEAD, operation model.RinOperation) {
	switch operation.Status {
	case model.RinOperationUnknown:
		c.JSON(http.StatusAccepted, gin.H{"status": "unknown"})
	case model.RinOperationExpired:
		c.JSON(http.StatusGone, gin.H{"status": "expired"})
	case model.RinOperationCompleted, model.RinOperationFailed:
		body, err := decryptRinReceipt(aead, operation)
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "rin operation receipt is unavailable"})
			return
		}
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

// The caller schedules this on a slow cadence. Tombstones prevent an expired
// key from causing a second upstream call.
func ExpireOldRinReceipts() error {
	return model.ExpireRinOperationReceipts(model.DB, time.Now().UTC().Add(-30*24*time.Hour))
}
