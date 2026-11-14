package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

const rinBudgetProfileHeader = "X-Rinspace-Budget-Profile"

// These are transport ceilings for the already dedicated Rin service token,
// not user grants or prices. The product freezes each user's actual budget;
// normal relay validation still bounds max_tokens before quota arithmetic.
type rinBudget struct {
	profile       string
	requestBytes  int
	responseBytes int
	messages      int
	messageBytes  int
	outputTokens  int
}

func readRinBudget(header http.Header) (rinBudget, bool) {
	budget := rinBudget{requestBytes: rinReceiptLimit, responseBytes: rinReceiptLimit, messages: rinAgentMessageLimit, messageBytes: rinAgentContentLimit, outputTokens: 4096}
	values := header.Values(rinBudgetProfileHeader)
	if len(values) == 0 {
		return budget, true
	}
	if len(values) != 1 {
		return rinBudget{}, false
	}
	switch values[0] {
	case "rin-agent/v2":
		budget.profile = values[0]
		budget.outputTokens = 393216
		budget.responseBytes = 4 << 20
	case "reader-learning/v1":
		budget.profile = values[0]
		budget.requestBytes = 8 << 20
		budget.responseBytes = 4 << 20
		budget.messages = 256
		budget.messageBytes = 1 << 20
		budget.outputTokens = 65536
	default:
		return rinBudget{}, false
	}
	return budget, true
}

func rinBudgetRequestHash(budget rinBudget, body []byte) string {
	// Preserve every accepted legacy key. New profiles must not reuse the same
	// key/body with a different response ceiling after an unknown invocation.
	if budget.profile != "" {
		body = append([]byte("rin-budget/v1\x00"+budget.profile+"\x00"), body...)
	}
	hash := sha256.Sum256(body)
	return hex.EncodeToString(hash[:])
}
