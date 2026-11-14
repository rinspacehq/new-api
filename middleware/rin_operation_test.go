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

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// This is the released receipt schema before learning-scoped content cleanup.
// Exercise real upgrades, rather than only migrating the new model twice.
type releasedRinOperation struct {
	ID                 uint64 `gorm:"primaryKey"`
	TokenID            int    `gorm:"uniqueIndex:idx_rin_operation_token_key;not null"`
	OperationKey       string `gorm:"size:128;uniqueIndex:idx_rin_operation_token_key;not null"`
	RequestHash        string `gorm:"size:64;not null"`
	Status             string `gorm:"size:16;not null;index:idx_rin_operation_status_created,priority:1"`
	HTTPStatus         int
	ResponseCiphertext []byte
	CreatedAt          time.Time `gorm:"index:idx_rin_operation_status_created,priority:2"`
	CompletedAt        *time.Time
}

func testRinOperationStore(t *testing.T, db *gorm.DB) {
	t.Helper()
	versionQuery := "SELECT version()"
	if db.Dialector.Name() == "sqlite" {
		versionQuery = "SELECT sqlite_version()"
	}
	var databaseVersion string
	require.NoError(t, db.Raw(versionQuery).Scan(&databaseVersion).Error)
	t.Logf("real database: %s %s", db.Dialector.Name(), databaseVersion)
	table := fmt.Sprintf("rin_operation_test_%d", time.Now().UnixNano())
	legacyTable := fmt.Sprintf("rin_legacy_token_%d", time.Now().UnixNano())
	legacyDB := db.Session(&gorm.Session{NewDB: true}).Table(legacyTable)
	require.NoError(t, legacyDB.AutoMigrate(&model.Token{}))
	require.NoError(t, legacyDB.Create(&model.Token{UserId: 91, Key: "legacy-rin-token"}).Error)
	t.Cleanup(func() { require.NoError(t, db.Migrator().DropTable(legacyTable)) })
	tableDB := db.Table(table)
	require.NoError(t, tableDB.AutoMigrate(&releasedRinOperation{}))
	completed := time.Now().UTC().Truncate(time.Millisecond)
	legacyReceipt := releasedRinOperation{TokenID: 91, OperationKey: "released-private-receipt", RequestHash: strings.Repeat("a", 64),
		Status: model.RinOperationCompleted, HTTPStatus: 200, ResponseCiphertext: []byte("original released encrypted receipt"), CompletedAt: &completed}
	require.NoError(t, tableDB.Create(&legacyReceipt).Error)
	require.NoError(t, tableDB.AutoMigrate(&model.RinOperation{}))
	require.NoError(t, tableDB.AutoMigrate(&model.RinOperation{}))
	var upgraded model.RinOperation
	require.NoError(t, tableDB.Where("id = ?", legacyReceipt.ID).Take(&upgraded).Error)
	assert.Equal(t, legacyReceipt.RequestHash, upgraded.RequestHash)
	assert.Equal(t, legacyReceipt.ResponseCiphertext, upgraded.ResponseCiphertext)
	assert.Empty(t, upgraded.BudgetProfile)
	assert.Nil(t, upgraded.ContentPurgedAt)
	t.Cleanup(func() { require.NoError(t, db.Migrator().DropTable(table)) })
	var legacy model.Token
	require.NoError(t, db.Session(&gorm.Session{NewDB: true}).Table(legacyTable).Where(map[string]any{"key": "legacy-rin-token"}).Take(&legacy).Error)
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

	// The new bounded profile retains complete large private responses. Exercise
	// the actual binary column through migration/replay on every supported DB.
	answer := bytes.Repeat([]byte("original-synthetic-receipt"), 90000)
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
	require.NoError(t, legacyDB.Where(map[string]any{"key": "legacy-rin-token"}).Take(&legacy).Error)
	assert.Equal(t, 91, legacy.UserId)

	learning, claimed, err := model.ClaimRinOperationWithProfile(operationDB(), 91, "learning-private", hash, "reader-learning/v1")
	require.NoError(t, err)
	assert.True(t, claimed)
	require.ErrorIs(t, model.PurgeRinLearningReceiptContent(operationDB(), 91, "learning-private"), model.ErrRinOperationPending)
	require.ErrorIs(t, model.PurgeRinLearningReceiptContent(operationDB(), 92, "learning-private"), gorm.ErrRecordNotFound)
	require.ErrorIs(t, model.PurgeRinLearningReceiptContent(operationDB(), 91, "released-private-receipt"), gorm.ErrRecordNotFound)
	require.NoError(t, model.CompleteRinOperation(operationDB(), learning.ID, model.RinOperationCompleted, 200, []byte("private learning receipt")))
	require.NoError(t, model.PurgeRinLearningReceiptContent(operationDB(), 91, "learning-private"))
	cleaned, claimed, err := model.ClaimRinOperationWithProfile(operationDB(), 91, "learning-private", hash, "reader-learning/v1")
	require.NoError(t, err)
	assert.False(t, claimed, "purging content must never release the original provider key")
	assert.Equal(t, model.RinOperationCompleted, cleaned.Status)
	assert.Equal(t, hash, cleaned.RequestHash)
	assert.Equal(t, 200, cleaned.HTTPStatus)
	assert.Empty(t, cleaned.ResponseCiphertext)
	require.NotNil(t, cleaned.ContentPurgedAt)
	require.NoError(t, model.PurgeRinLearningReceiptContent(operationDB(), 91, "learning-private"))
	require.Error(t, model.CompleteRinOperation(operationDB(), learning.ID, model.RinOperationCompleted, 200, []byte("late replacement")))
	_, _, err = model.ClaimRinOperationWithProfile(operationDB(), 91, "learning-private", hash, "rin-agent/v2")
	require.ErrorIs(t, err, model.ErrRinOperationConflict)
	require.NoError(t, tableDB.AutoMigrate(&model.RinOperation{}))
	var after model.RinOperation
	require.NoError(t, operationDB().Where("id = ?", cleaned.ID).Take(&after).Error)
	assert.Equal(t, cleaned.ContentPurgedAt, after.ContentPurgedAt)
	assert.Empty(t, after.ResponseCiphertext)

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
	aborted, err := model.AbortUnclaimedRinOperation(operationDB(), 91, "rin-never-sent")
	require.NoError(t, err)
	assert.Equal(t, model.RinOperationExpired, aborted.Status)
	repeatedAbort, err := model.AbortUnclaimedRinOperation(operationDB(), 91, "rin-never-sent")
	require.NoError(t, err)
	assert.Equal(t, aborted.ID, repeatedAbort.ID)
	_, claimed, err = model.ClaimRinOperation(operationDB(), 91, "rin-never-sent", hash)
	require.ErrorIs(t, err, model.ErrRinOperationConflict)
	assert.False(t, claimed, "a late request must not call the provider")
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
	assert.True(t, rinTokenAllowed(91, http.MethodPost, "/v1/rin/operations/op-one/abort"))
	assert.False(t, rinTokenAllowed(91, http.MethodGet, "/v1/rin/operations/op-one/abort"))
	assert.False(t, rinTokenAllowed(91, http.MethodPost, "/v1/rin/operations/op-one/abort/extra"))
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

func TestRinOperationStoreMySQL(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("TEST_MYSQL_DSN"))
	if dsn == "" {
		t.Skip("TEST_MYSQL_DSN is not configured")
	}
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
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
	engine.POST("/v1/rin/operations/:key/abort", AbortMissingRinOperation())
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
	abortedCompleted := httptest.NewRecorder()
	engine.ServeHTTP(abortedCompleted, httptest.NewRequest(http.MethodPost, "/v1/rin/operations/op-one/abort", nil))
	assert.Equal(t, first.Body.String(), abortedCompleted.Body.String())
	assert.Equal(t, model.RinOperationCompleted, abortedCompleted.Header().Get(rinOperationStatusHeader))
	assert.Equal(t, 1, calls)
	abortedMissing := httptest.NewRecorder()
	engine.ServeHTTP(abortedMissing, httptest.NewRequest(http.MethodPost, "/v1/rin/operations/not-sent/abort", nil))
	assert.Equal(t, http.StatusGone, abortedMissing.Code)
	assert.Equal(t, model.RinOperationExpired, abortedMissing.Header().Get(rinOperationStatusHeader))
	assert.Equal(t, http.StatusConflict, send(http.MethodPost, "not-sent", requestBody).Code)
	assert.Equal(t, 1, calls, "a late request must not call the model")
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
	abortedUnknown := httptest.NewRecorder()
	engine.ServeHTTP(abortedUnknown, httptest.NewRequest(http.MethodPost, "/v1/rin/operations/op-stream/abort", nil))
	assert.Equal(t, http.StatusAccepted, abortedUnknown.Code)
	assert.Equal(t, model.RinOperationUnknown, abortedUnknown.Header().Get(rinOperationStatusHeader))
	assert.Equal(t, 2, calls)

	var stored model.RinOperation
	require.NoError(t, db.First(&stored).Error)
	assert.NotContains(t, string(stored.ResponseCiphertext), "private answer")
	require.NoError(t, model.ExpireRinOperationReceipts(db, time.Now().Add(time.Minute), time.Now().Add(time.Minute)))
	assert.Equal(t, http.StatusGone, send(http.MethodPost, "op-one", requestBody).Code)
	assert.Equal(t, 2, calls)
}

func TestRinOperationReceiptAcceptsAgentToolProtocol(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open("file:rin_agent_receipts?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&model.RinOperation{}))
	previous := model.DB
	model.DB = db
	t.Cleanup(func() { model.DB = previous })
	t.Setenv("RINSPACE_RIN_TOKEN_ID", "91")
	t.Setenv("RINSPACE_RIN_RECEIPT_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32)))
	engine := gin.New()
	engine.Use(func(c *gin.Context) { c.Set("token_id", 91); c.Next() })
	engine.Use(RinTokenScope(), RinOperationReceipt())
	calls := 0
	engine.POST("/v1/chat/completions", func(c *gin.Context) {
		calls++
		c.JSON(http.StatusOK, gin.H{
			"id": "provider-agent-1", "model": "deepseek-flash",
			"choices": []gin.H{{
				"message": gin.H{"role": "assistant", "content": "", "tool_calls": []gin.H{{
					"id": "call-1", "type": "function",
					"function": gin.H{"name": "read_project_files", "arguments": `{"path":"main.tex"}`},
				}}},
				"finish_reason": "tool_calls",
			}},
			"usage": gin.H{"prompt_tokens": 20, "completion_tokens": 4, "prompt_cache_hit_tokens": 5, "prompt_cache_miss_tokens": 15},
		})
	})
	engine.GET("/v1/rin/operations/:key", ReadRinOperationReceipt())

	tool := `{"type":"function","function":{"name":"read_project_files","description":"Read one project file.","parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false}}}`
	initial := `{"model":"deepseek-flash","messages":[{"role":"system","content":"Use only declared tools."},{"role":"user","content":"Read main.tex."}],"tools":[` + tool + `],"tool_choice":"auto","stream":false,"max_tokens":16,"temperature":0.2,"thinking":{"type":"disabled"}}`
	send := func(key, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
		request.Header.Set(rinOperationHeader, key)
		response := httptest.NewRecorder()
		engine.ServeHTTP(response, request)
		return response
	}
	first := send("agent-one", initial)
	require.Equal(t, http.StatusOK, first.Code)
	assert.Equal(t, model.RinOperationCompleted, first.Header().Get(rinOperationStatusHeader))
	assert.Contains(t, first.Body.String(), "call-1")
	assert.Equal(t, first.Body.String(), send("agent-one", initial).Body.String())
	receipt := httptest.NewRecorder()
	engine.ServeHTTP(receipt, httptest.NewRequest(http.MethodGet, "/v1/rin/operations/agent-one", nil))
	assert.Equal(t, first.Body.String(), receipt.Body.String())
	assert.Equal(t, 1, calls)

	continued := `{"model":"deepseek-flash","messages":[{"role":"system","content":"Use only declared tools."},{"role":"user","content":"Read main.tex."},{"role":"assistant","tool_calls":[{"id":"call-1","type":"function","function":{"name":"read_project_files","arguments":"{\"path\":\"main.tex\"}"}}]},{"role":"tool","content":"file contents","tool_call_id":"call-1"}],"tools":[` + tool + `],"tool_choice":"auto","stream":false,"max_tokens":16,"temperature":0.2,"thinking":{"type":"disabled"}}`
	assert.Equal(t, http.StatusOK, send("agent-two", continued).Code)
	assert.Equal(t, 2, calls)

	for key, invalid := range map[string]string{
		"agent-extra-field": strings.TrimSuffix(initial, "}") + `,"n":2}`,
		"agent-bad-schema":  strings.Replace(initial, `"parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false}`, `"parameters":[]`, 1),
		"agent-bad-tool":    strings.Replace(initial, `"name":"read_project_files"`, `"name":"read.project"`, 1),
		"agent-orphan-result": strings.Replace(initial,
			`{"role":"user","content":"Read main.tex."}`,
			`{"role":"tool","content":"file contents","tool_call_id":"missing"}`, 1),
		"agent-over-limit": strings.Replace(initial, `"max_tokens":16`, `"max_tokens":4097`, 1),
	} {
		assert.Equal(t, http.StatusBadRequest, send(key, invalid).Code, key)
	}
	assert.Equal(t, 2, calls, "invalid agent requests must not reach the provider")
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

func TestRinBudgetProfilesBindReplayAndRemainServiceScoped(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open("file:rin_budget_profiles?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&model.RinOperation{}))
	previous := model.DB
	model.DB = db
	t.Cleanup(func() { model.DB = previous })
	t.Setenv("RINSPACE_RIN_TOKEN_ID", "91")
	t.Setenv("RINSPACE_RIN_RECEIPT_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	engine := gin.New()
	engine.Use(func(c *gin.Context) {
		id := 91
		if c.GetHeader("X-Fixture-Token") == "foreign" {
			id = 92
		}
		c.Set("token_id", id)
		c.Next()
	})
	engine.Use(RinTokenScope(), RinOperationReceipt())
	calls := 0
	engine.POST("/v1/chat/completions", func(c *gin.Context) {
		calls++
		assert.Empty(t, c.GetHeader(rinBudgetProfileHeader), "internal profile must not leak to the provider")
		text := "synthetic answer"
		if c.GetHeader(rinOperationHeader) == "reader-large" {
			text = strings.Repeat("x", 2<<20)
		}
		if c.GetHeader(rinOperationHeader) == "reader-overflow" {
			text = strings.Repeat("x", 4<<20)
		}
		c.JSON(http.StatusOK, gin.H{"text": text})
	})
	engine.GET("/v1/rin/operations/:key", ReadRinOperationReceipt())
	tool := map[string]any{"type": "function", "function": map[string]any{"name": "read_pages", "description": "Read bounded pages.", "parameters": map[string]any{"type": "object", "properties": map[string]any{}}}}
	body := func(messages int, text string, tokens int) string {
		list := []map[string]any{{"role": "system", "content": "Use only declared tools."}}
		for range messages - 1 {
			list = append(list, map[string]any{"role": "user", "content": text})
		}
		encoded, err := common.Marshal(map[string]any{"model": "deepseek-flash", "messages": list, "tools": []any{tool}, "tool_choice": "auto", "stream": false, "max_tokens": tokens, "temperature": 0.2, "thinking": map[string]string{"type": "disabled"}})
		require.NoError(t, err)
		return string(encoded)
	}
	send := func(key, profile, body string, foreign, duplicate bool) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
		if key != "" {
			request.Header.Set(rinOperationHeader, key)
		}
		if profile != "" {
			request.Header.Set(rinBudgetProfileHeader, profile)
		}
		if duplicate {
			request.Header.Add(rinBudgetProfileHeader, "reader-learning/v1")
		}
		if foreign {
			request.Header.Set("X-Fixture-Token", "foreign")
		}
		response := httptest.NewRecorder()
		engine.ServeHTTP(response, request)
		return response
	}
	large := body(100, strings.Repeat("a", 700), 32768)
	assert.Equal(t, http.StatusBadRequest, send("legacy-large", "", large, false, false).Code)
	assert.Equal(t, http.StatusBadRequest, send("agent-many", "rin-agent/v2", large, false, false).Code)
	first := send("reader-large", "reader-learning/v1", large, false, false)
	require.Equal(t, http.StatusOK, first.Code)
	assert.Greater(t, first.Body.Len(), 1<<20)
	assert.Equal(t, first.Body.String(), send("reader-large", "reader-learning/v1", large, false, false).Body.String())
	query := httptest.NewRecorder()
	engine.ServeHTTP(query, httptest.NewRequest(http.MethodGet, "/v1/rin/operations/reader-large", nil))
	assert.Equal(t, first.Body.String(), query.Body.String())
	assert.Equal(t, 1, calls)
	assert.Equal(t, http.StatusOK, send("reader-page", "reader-learning/v1", body(2, strings.Repeat("a", 80000), 32768), false, false).Code)
	assert.Equal(t, http.StatusBadRequest, send("agent-page", "rin-agent/v2", body(2, strings.Repeat("a", 80000), 32768), false, false).Code)
	shared := body(2, "hello", 4096)
	require.Equal(t, http.StatusOK, send("shared-key", "reader-learning/v1", shared, false, false).Code)
	assert.Equal(t, http.StatusConflict, send("shared-key", "rin-agent/v2", shared, false, false).Code)
	assert.Equal(t, http.StatusOK, send("old-key", "", shared, false, false).Code)
	assert.Equal(t, http.StatusConflict, send("old-key", "rin-agent/v2", shared, false, false).Code)
	assert.Equal(t, http.StatusOK, send("agent-output", "rin-agent/v2", body(2, "hello", 393216), false, false).Code)
	assert.Equal(t, http.StatusServiceUnavailable, send("reader-overflow", "reader-learning/v1", shared, false, false).Code)
	countAfterOverflow := calls
	assert.Equal(t, http.StatusAccepted, send("reader-overflow", "reader-learning/v1", shared, false, false).Code)
	assert.Equal(t, countAfterOverflow, calls, "an oversized receipt must remain unknown without another model call")
	before := calls
	for _, test := range []struct {
		name, profile      string
		foreign, duplicate bool
		status             int
	}{
		{"unknown", "reader-learning/v999", false, false, http.StatusBadRequest},
		{"duplicate", "reader-learning/v1", false, true, http.StatusBadRequest},
		{"foreign", "reader-learning/v1", true, false, http.StatusForbidden},
	} {
		assert.Equal(t, test.status, send(test.name, test.profile, shared, test.foreign, test.duplicate).Code, test.name)
	}
	assert.Equal(t, http.StatusForbidden, send("", "reader-learning/v1", shared, true, false).Code)
	assert.Equal(t, http.StatusBadRequest, send("reader-output", "reader-learning/v1", body(2, "hello", 65537), false, false).Code)
	assert.Equal(t, http.StatusBadRequest, send("agent-output-over", "rin-agent/v2", body(2, "hello", 393217), false, false).Code)
	assert.Equal(t, http.StatusBadRequest, send("reader-messages", "reader-learning/v1", body(257, "hello", 32768), false, false).Code)
	assert.Equal(t, http.StatusBadRequest, send("reader-message", "reader-learning/v1", body(2, strings.Repeat("x", (1<<20)+1), 32768), false, false).Code)
	assert.Equal(t, http.StatusRequestEntityTooLarge, send("reader-bytes", "reader-learning/v1", strings.Repeat(" ", (8<<20)+1), false, false).Code)
	assert.Equal(t, before, calls, "invalid scopes/limits must not invoke the provider")
}
