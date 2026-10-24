package model

import (
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestRinReceiptTokenCanReadAfterQuotaExhaustion(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:rin_exhausted_token?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&Token{}))
	previousDB, previousRedis, previousKeyCol := DB, common.RedisEnabled, commonKeyCol
	DB, common.RedisEnabled, commonKeyCol = db, false, "`key`"
	t.Cleanup(func() { DB, common.RedisEnabled, commonKeyCol = previousDB, previousRedis, previousKeyCol })
	token := Token{Id: 91, UserId: 7, Key: "rin-exhausted-test-key", Status: common.TokenStatusEnabled,
		ExpiredTime: -1, RemainQuota: 0}
	require.NoError(t, db.Create(&token).Error)
	_, err = ValidateUserToken(token.Key)
	require.ErrorIs(t, err, ErrTokenInvalid)
	loaded, err := ValidateRinReceiptToken(token.Key, token.Id)
	require.NoError(t, err)
	assert.Equal(t, token.Id, loaded.Id)
	_, err = ValidateRinReceiptToken(token.Key, token.Id+1)
	require.ErrorIs(t, err, ErrTokenInvalid)
	require.NoError(t, db.Model(&token).Update("expired_time", time.Now().Add(-time.Minute).Unix()).Error)
	_, err = ValidateRinReceiptToken(token.Key, token.Id)
	require.ErrorIs(t, err, ErrTokenInvalid)
}
