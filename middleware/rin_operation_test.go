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
	"gorm.io/driver/mysql"
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
	require.NoError(t, tableDB.AutoMigrate(&model.RinOperation{}), "migration must be repeatable")
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
	_, claimed, err = model.ClaimRinOperation(operationDB(), 92, "rin-01", hash)
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

	require.NoError(t, model.ExpireRinOperationReceipts(operationDB(), time.Now().Add(time.Minute)))
	stored, claimed, err = model.ClaimRinOperation(operationDB(), 91, "rin-01", hash)
	require.NoError(t, err)
	assert.False(t, claimed)
	assert.Equal(t, model.RinOperationExpired, stored.Status)
	assert.Empty(t, stored.ResponseCiphertext)
}

func TestRinOperationStoreSQLite(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:rin_receipts?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
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
		c.JSON(http.StatusOK, gin.H{"choices": []gin.H{{"message": gin.H{"content": "private answer"}}}})
	})
	engine.GET("/v1/rin/operations/:key", ReadRinOperationReceipt())
	engine.POST("/v1/completions", func(c *gin.Context) { c.Status(http.StatusOK) })

	requestBody := `{"model":"deepseek-flash","stream":false,"max_tokens":100,"messages":[]}`
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
	assert.Contains(t, first.Body.String(), "private answer")
	assert.Equal(t, first.Body.String(), send(http.MethodPost, "op-one", requestBody).Body.String())
	assert.Equal(t, first.Body.String(), send(http.MethodGet, "op-one", "").Body.String())
	assert.Equal(t, 1, calls)
	withoutKey := httptest.NewRecorder()
	engine.ServeHTTP(withoutKey, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(requestBody)))
	assert.Equal(t, http.StatusBadRequest, withoutKey.Code)
	wrongRoute := httptest.NewRecorder()
	engine.ServeHTTP(wrongRoute, httptest.NewRequest(http.MethodPost, "/v1/completions", nil))
	assert.Equal(t, http.StatusForbidden, wrongRoute.Code)
	assert.Equal(t, http.StatusConflict, send(http.MethodPost, "op-one", requestBody+" ").Code)
	assert.Equal(t, 1, calls)

	var stored model.RinOperation
	require.NoError(t, db.First(&stored).Error)
	assert.NotContains(t, string(stored.ResponseCiphertext), "private answer")
	require.NoError(t, model.ExpireRinOperationReceipts(db, time.Now().Add(time.Minute)))
	assert.Equal(t, http.StatusGone, send(http.MethodPost, "op-one", requestBody).Code)
	assert.Equal(t, 1, calls)
}
