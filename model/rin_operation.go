package model

import (
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// RinOperation is the durable boundary around one non-streaming Rin model call.
// A claimed operation remains unknown after a process crash; callers must never
// replay the upstream call merely because the answer is unavailable.
type RinOperation struct {
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

const (
	RinOperationUnknown   = "unknown"
	RinOperationCompleted = "completed"
	RinOperationFailed    = "failed"
	RinOperationExpired   = "expired"
)

var ErrRinOperationConflict = errors.New("rin operation key has a different request")

// ClaimRinOperation returns claimed=true only to the one caller permitted to
// start the upstream call. An existing unknown operation is never reclaimed.
func ClaimRinOperation(db *gorm.DB, tokenID int, key, hash string) (RinOperation, bool, error) {
	if tokenID <= 0 || len(key) == 0 || len(key) > 128 || len(hash) != 64 {
		return RinOperation{}, false, errors.New("invalid rin operation identity")
	}
	operation := RinOperation{
		TokenID: tokenID, OperationKey: key, RequestHash: hash,
		Status: RinOperationUnknown,
	}
	result := db.Clauses(clause.OnConflict{DoNothing: true}).Create(&operation)
	if result.Error != nil {
		return RinOperation{}, false, result.Error
	}
	if result.RowsAffected == 1 {
		return operation, true, nil
	}
	if err := db.Where("token_id = ? AND operation_key = ?", tokenID, key).Take(&operation).Error; err != nil {
		return RinOperation{}, false, err
	}
	if operation.RequestHash != hash {
		return RinOperation{}, false, ErrRinOperationConflict
	}
	return operation, false, nil
}

// CompleteRinOperation is compare-and-set: a duplicate or late writer cannot
// replace a receipt once the operation has reached a terminal state.
func CompleteRinOperation(db *gorm.DB, operationID uint64, status string, httpStatus int, ciphertext []byte) error {
	if operationID == 0 || (status != RinOperationCompleted && status != RinOperationFailed) ||
		httpStatus < 200 || httpStatus > 599 || len(ciphertext) == 0 {
		return errors.New("invalid rin operation receipt")
	}
	now := time.Now().UTC()
	result := db.Model(&RinOperation{}).Where("id = ? AND status = ?", operationID, RinOperationUnknown).Updates(map[string]any{
		"status": status, "http_status": httpStatus,
		"response_ciphertext": ciphertext, "completed_at": now,
	})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return errors.New("rin operation receipt was not accepted")
	}
	return nil
}

// ExpireRinOperationReceipts removes old private answers and expires abandoned
// unknown operations. Both remain as tombstones so their keys cannot call the
// upstream model a second time.
func ExpireRinOperationReceipts(db *gorm.DB, completedBefore, unknownBefore time.Time) error {
	if err := db.Model(&RinOperation{}).
		Where("status IN ? AND completed_at < ?", []string{RinOperationCompleted, RinOperationFailed}, completedBefore).
		Updates(map[string]any{"status": RinOperationExpired, "response_ciphertext": nil}).Error; err != nil {
		return err
	}
	return db.Model(&RinOperation{}).
		Where("status = ? AND created_at < ?", RinOperationUnknown, unknownBefore).
		Update("status", RinOperationExpired).Error
}
