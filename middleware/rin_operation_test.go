package middleware

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func testRinOperationStore(t *testing.T, db *gorm.DB) {
	t.Helper()
	table := fmt.Sprintf("rin_operation_test_%d", time.Now().UnixNano())
	legacyTable := fmt.Sprintf("rin_legacy_token_%d", time.Now().UnixNano())
	legacyDB := db.Session(&gorm.Session{NewDB: true}).Table(legacyTable)
	require.NoError(t, legacyDB.AutoMigrate(&model.Token{}))
	require.NoError(t, legacyDB.Create(&model.Token{UserId: 91, Key: "legacy-rin-token"}).Error)
	t.Cleanup(func() { require.NoError(t, db.Migrator().DropTable(legacyTable)) })
	tableDB := db.Table(table)
	require.NoError(t, tableDB.AutoMigrate(&model.RinOperation{}))
	t.Cleanup(func() { require.NoError(t, db.Migrator().DropTable(table)) })
	var legacy model.Token
	require.NoError(t, db.Session(&gorm.Session{NewDB: true}).Table(legacyTable).Where("key = ?", "legacy-rin-token").Take(&legacy).Error)
	assert.Equal(t, 91, legacy.UserId, "upgrading must preserve existing token data")
	operationDB := func() *gorm.DB { return db.Session(&gorm.Session{NewDB: true}).Table(table) }

	const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	var claims [2]bool
	var operations [2]model.RinOperation
	var errs [2]error
	var wg sync.WaitGroup
	for i := range claims {
		wg.Go(func() {
			operations[i], claims[i], errs[i] = model.ClaimRinOperation(operationDB(), 91, "rin-01", hash)
		})
	}
	wg.Wait()
	require.NoError(t, errs[0])
	require.NoError(t, errs[1])
	assert.NotEqual(t, claims[0], claims[1], "one request must own the model call")
	assert.Equal(t, operations[0].ID, operations[1].ID)
	assert.Equal(t, model.RinOperationUnknown, operations[0].Status)

	_, claimed, err := model.ClaimRinOperation(operationDB(), 91, "rin-01", strings.Repeat("f", 64))
	require.ErrorIs(t, err, model.ErrRinOperationConflict)
	assert.False(t, claimed)
	unknown, claimed, err := model.ClaimRinOperation(operationDB(), 92, "rin-01", hash)
	require.NoError(t, err)
	assert.True(t, claimed)

	answer := []byte("encrypted answer")
	require.NoError(t, model.CompleteRinOperation(operationDB(), operations[0].ID, model.RinOperationCompleted, 200, answer))
	require.Error(t, model.CompleteRinOperation(operationDB(), operations[0].ID, model.RinOperationCompleted, 200, []byte("replacement")))
	stored, claimed, err := model.ClaimRinOperation(operationDB(), 91, "rin-01", hash)
	require.NoError(t, err)
	assert.False(t, claimed)
	assert.Equal(t, model.RinOperationCompleted, stored.Status)
	assert.True(t, bytes.Equal(answer, stored.ResponseCiphertext))
	require.NoError(t, tableDB.AutoMigrate(&model.RinOperation{}), "upgrade over a completed receipt must preserve it")
	require.NoError(t, tableDB.AutoMigrate(&model.RinOperation{}), "a repeated startup migration must be harmless")
	require.NoError(t, operationDB().Where("token_id = ? AND operation_key = ?", 91, "rin-01").Take(&stored).Error)
	assert.Equal(t, model.RinOperationCompleted, stored.Status)
	assert.True(t, bytes.Equal(answer, stored.ResponseCiphertext))
	require.NoError(t, legacyDB.Where("key = ?", "legacy-rin-token").Take(&legacy).Error)
	assert.Equal(t, 91, legacy.UserId)

	require.NoError(t, model.ExpireRinOperationReceipts(operationDB(), time.Now().Add(time.Minute), time.Now().Add(-time.Minute)))
	stillUnknown, claimed, err := model.ClaimRinOperation(operationDB(), 92, "rin-01", hash)
	require.NoError(t, err)
	assert.False(t, claimed)
	assert.Equal(t, unknown.ID, stillUnknown.ID)
	assert.Equal(t, model.RinOperationUnknown, stillUnknown.Status)
	require.NoError(t, model.ExpireRinOperationReceipts(operationDB(), time.Now().Add(time.Minute), time.Now().Add(time.Minute)))
	stored, claimed, err = model.ClaimRinOperation(operationDB(), 91, "rin-01", hash)
	require.NoError(t, err)
	assert.False(t, claimed)
	assert.Equal(t, model.RinOperationExpired, stored.Status)
	assert.Empty(t, stored.ResponseCiphertext)
	expiredUnknown, claimed, err := model.ClaimRinOperation(operationDB(), 92, "rin-01", hash)
	require.NoError(t, err)
	assert.False(t, claimed, "an expired unknown operation must never call upstream again")
	assert.Equal(t, model.RinOperationExpired, expiredUnknown.Status)
}

func TestRinOperationStoreSQLite(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:rin_receipts?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	testRinOperationStore(t, db)
}

func TestRinDedicatedTokenCannotUseOtherTokenRoutes(t *testing.T) {
	t.Setenv("RINSPACE_RIN_TOKEN_ID", "91")
	for _, route := range []struct{ method, path string }{
		{http.MethodGet, "/v1/models"},
		{http.MethodPost, "/v1beta/models/deepseek-flash:generateContent"},
		{http.MethodGet, "/v1beta/openai/models"},
		{http.MethodPost, "/v1/completions"},
	} {
		assert.False(t, rinTokenAllowed(91, route.method, route.path), "%s %s", route.method, route.path)
		assert.True(t, rinTokenAllowed(92, route.method, route.path), "other tokens must be unaffected")
	}
	assert.True(t, rinTokenAllowed(91, http.MethodPost, "/v1/chat/completions"))
	assert.True(t, rinTokenAllowed(91, http.MethodGet, "/v1/rin/operations/op-one"))
	assert.False(t, rinTokenAllowed(91, http.MethodPost, "/v1/rin/operations/op-one"))
}

func TestRinOperationStorePostgreSQL(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("TEST_POSTGRES_DSN is not configured")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	testRinOperationStore(t, db)
}

func TestRinOperationReceiptNeverRepeatsModelCall(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open("file:rin_http_receipts?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.RinOperation{}))
	previous := model.DB
	model.DB = db
	t.Cleanup(func() { model.DB = previous })
	t.Setenv("RINSPACE_RIN_TOKEN_ID", "91")
	t.Setenv("RINSPACE_RIN_RECEIPT_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	engine := gin.New()
	engine.Use(func(c *gin.Context) { c.Set("token_id", 91); c.Next() })
	engine.Use(RinTokenScope())
	engine.Use(RinOperationReceipt())
	calls := 0
	engine.POST("/v1/chat/completions", func(c *gin.Context) {
		calls++
		if c.GetHeader(rinOperationHeader) == "op-stream" {
			c.Header("Content-Type", "text/event-stream")
			_, _ = c.Writer.Write([]byte("data: partial\n\n"))
			c.Writer.Flush()
			return
		}
		c.JSON(http.StatusOK, gin.H{"choices": []gin.H{{"message": gin.H{"content": "private answer"}}}})
		c.Writer.Flush() // Matches the normal relay's final flush after JSON.
	})
	engine.GET("/v1/rin/operations/:key", ReadRinOperationReceipt())
	engine.POST("/v1/completions", func(c *gin.Context) { c.Status(http.StatusOK) })

	requestBody := `{"model":"deepseek-flash","stream":false,"max_tokens":100,"temperature":0.68,"thinking":{"type":"disabled"},"messages":[{"role":"system","content":"Rin"},{"role":"user","content":"hello"}]}`
	send := func(method, key, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, "/v1/chat/completions", strings.NewReader(body))
		if method == http.MethodGet {
			request = httptest.NewRequest(method, "/v1/rin/operations/"+key, nil)
		} else {
			request.Header.Set(rinOperationHeader, key)
		}
		response := httptest.NewRecorder()
		engine.ServeHTTP(response, request)
		return response
	}
	first := send(http.MethodPost, "op-one", requestBody)
	require.Equal(t, http.StatusOK, first.Code)
	assert.Equal(t, model.RinOperationCompleted, first.Header().Get(rinOperationStatusHeader))
	assert.Contains(t, first.Body.String(), "private answer")
	assert.Equal(t, first.Body.String(), send(http.MethodPost, "op-one", requestBody).Body.String())
	queried := send(http.MethodGet, "op-one", "")
	assert.Equal(t, first.Body.String(), queried.Body.String())
	assert.Equal(t, model.RinOperationCompleted, queried.Header().Get(rinOperationStatusHeader))
	assert.Equal(t, 1, calls)
	withoutKey := httptest.NewRecorder()
	engine.ServeHTTP(withoutKey, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(requestBody)))
	assert.Equal(t, http.StatusBadRequest, withoutKey.Code)
	wrongRoute := httptest.NewRecorder()
	engine.ServeHTTP(wrongRoute, httptest.NewRequest(http.MethodPost, "/v1/completions", nil))
	assert.Equal(t, http.StatusForbidden, wrongRoute.Code)
	assert.Equal(t, http.StatusConflict, send(http.MethodPost, "op-one", requestBody+" ").Code)
	for key, invalid := range map[string]string{
		"multiple-answers": requestBody[:len(requestBody)-1] + `,"n":2}`,
		"null-stream":      strings.Replace(requestBody, `"stream":false`, `"stream":null`, 1),
		"extra-message":    strings.Replace(requestBody, `"role":"user","content":"hello"`, `"role":"user","content":"hello","name":"other"`, 1),
	} {
		assert.Equal(t, http.StatusBadRequest, send(http.MethodPost, key, invalid).Code, key)
	}
	assert.Equal(t, 1, calls)
	stream := send(http.MethodPost, "op-stream", requestBody)
	assert.Equal(t, http.StatusServiceUnavailable, stream.Code)
	assert.Equal(t, model.RinOperationUnknown, send(http.MethodGet, "op-stream", "").Header().Get(rinOperationStatusHeader))
	assert.Equal(t, 2, calls)

	var stored model.RinOperation
	require.NoError(t, db.First(&stored).Error)
	assert.NotContains(t, string(stored.ResponseCiphertext), "private answer")
	require.NoError(t, model.ExpireRinOperationReceipts(db, time.Now().Add(time.Minute), time.Now().Add(time.Minute)))
	assert.Equal(t, http.StatusGone, send(http.MethodPost, "op-one", requestBody).Code)
	assert.Equal(t, 2, calls)
}

func TestRinReceiptQueryDistinguishesStoredFailureFromUnavailable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open("file:rin_failed_receipts?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&model.RinOperation{}))
	previous := model.DB
	model.DB = db
	t.Cleanup(func() { model.DB = previous })
	t.Setenv("RINSPACE_RIN_TOKEN_ID", "91")
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	t.Setenv("RINSPACE_RIN_RECEIPT_KEY", key)
	engine := gin.New()
	engine.Use(func(c *gin.Context) { c.Set("token_id", 91); c.Next() })
	engine.Use(RinTokenScope(), RinOperationReceipt())
	calls := 0
	engine.POST("/v1/chat/completions", func(c *gin.Context) {
		calls++
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "upstream unavailable"})
	})
	engine.GET("/v1/rin/operations/:key", ReadRinOperationReceipt())

	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"deepseek-flash","stream":false,"max_tokens":100,"temperature":0.68,"thinking":{"type":"disabled"},"messages":[{"role":"system","content":"Rin"},{"role":"user","content":"hello"}]}`))
	request.Header.Set(rinOperationHeader, "failed-one")
	first := httptest.NewRecorder()
	engine.ServeHTTP(first, request)
	require.Equal(t, http.StatusServiceUnavailable, first.Code)
	assert.Equal(t, model.RinOperationFailed, first.Header().Get(rinOperationStatusHeader))
	query := httptest.NewRequest(http.MethodGet, "/v1/rin/operations/failed-one", nil)
	replay := httptest.NewRecorder()
	engine.ServeHTTP(replay, query)
	assert.Equal(t, first.Body.String(), replay.Body.String())
	assert.Equal(t, model.RinOperationFailed, replay.Header().Get(rinOperationStatusHeader))
	assert.Equal(t, 1, calls)

	t.Setenv("RINSPACE_RIN_RECEIPT_KEY", "")
	unavailable := httptest.NewRecorder()
	engine.ServeHTTP(unavailable, httptest.NewRequest(http.MethodGet, "/v1/rin/operations/failed-one", nil))
	assert.Equal(t, http.StatusServiceUnavailable, unavailable.Code)
	assert.Empty(t, unavailable.Header().Get(rinOperationStatusHeader))
}
