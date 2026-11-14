package middleware

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestRinLearningContentPurgeIsScopedAndCannotReplayTheModel(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := gorm.Open(sqlite.Open("file:rin_content_purge?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, db.AutoMigrate(&model.RinOperation{}))
	previous := model.DB
	model.DB = db
	t.Cleanup(func() { model.DB = previous })
	t.Setenv("RINSPACE_RIN_TOKEN_ID", "91")
	t.Setenv("RINSPACE_RIN_RECEIPT_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	actor := 91
	engine := gin.New()
	engine.Use(func(c *gin.Context) { c.Set("token_id", actor); c.Next() }, RinTokenScope())
	engine.DELETE("/v1/rin/operations/:key/content", PurgeRinLearningReceiptContent())
	engine.GET("/v1/rin/operations/:key", ReadRinOperationReceipt())
	engine.Use(RinOperationReceipt())
	calls := 0
	engine.POST("/v1/chat/completions", func(c *gin.Context) {
		calls++
		c.JSON(http.StatusOK, gin.H{"id": "synthetic-response", "choices": []gin.H{{"message": gin.H{"content": "private original learning answer"}}}})
	})
	send := func(method, path, profile, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		if profile != "" {
			request.Header.Set(rinBudgetProfileHeader, profile)
		}
		request.Header.Set(rinOperationHeader, "learning-one")
		response := httptest.NewRecorder()
		engine.ServeHTTP(response, request)
		return response
	}
	body := `{"model":"deepseek-flash","stream":false,"max_tokens":100,"temperature":0.68,"thinking":{"type":"disabled"},"messages":[{"role":"system","content":"Rin"},{"role":"user","content":"Original synthetic question"}]}`
	require.Equal(t, http.StatusOK, send(http.MethodPost, "/v1/chat/completions", "reader-learning/v1", body).Code)
	require.Equal(t, 1, calls)
	const path = "/v1/rin/operations/learning-one/content"
	require.Equal(t, http.StatusForbidden, send(http.MethodDelete, path, "", "").Code)
	require.Equal(t, http.StatusForbidden, send(http.MethodDelete, path, "rin-agent/v2", "").Code)
	actor = 92
	require.Equal(t, http.StatusForbidden, send(http.MethodDelete, path, "reader-learning/v1", "").Code)
	actor = 91
	require.Equal(t, http.StatusBadRequest, send(http.MethodDelete, path+"?actor=other", "reader-learning/v1", "").Code)
	require.Equal(t, http.StatusBadRequest, send(http.MethodDelete, path, "reader-learning/v1", `{}`).Code)
	require.Equal(t, http.StatusNotFound, send(http.MethodDelete, "/v1/rin/operations/missing/content", "reader-learning/v1", "").Code)
	_, _, err = model.ClaimRinOperation(db, 91, "legacy-private", strings.Repeat("a", 64))
	require.NoError(t, err)
	require.Equal(t, http.StatusNotFound, send(http.MethodDelete, "/v1/rin/operations/legacy-private/content", "reader-learning/v1", "").Code)
	_, _, err = model.ClaimRinOperationWithProfile(db, 91, "pending-private", strings.Repeat("b", 64), "reader-learning/v1")
	require.NoError(t, err)
	require.Equal(t, http.StatusConflict, send(http.MethodDelete, "/v1/rin/operations/pending-private/content", "reader-learning/v1", "").Code)
	require.Equal(t, http.StatusNoContent, send(http.MethodDelete, path, "reader-learning/v1", "").Code)
	require.Equal(t, http.StatusNoContent, send(http.MethodDelete, path, "reader-learning/v1", "").Code)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		target := "/v1/rin/operations/learning-one"
		payload := ""
		if method == http.MethodPost {
			target = "/v1/chat/completions"
			payload = body
		}
		response := send(method, target, "reader-learning/v1", payload)
		require.Equal(t, http.StatusGone, response.Code)
		require.Equal(t, "content_deleted", response.Header().Get(rinOperationStatusHeader))
		require.NotContains(t, response.Body.String(), "private original")
	}
	require.Equal(t, 1, calls, "content cleanup must never release a claimed provider key")
}
