package pawpal

import (
	"crypto/subtle"
	"fmt"
)

type WebhookOutcome string

const (
	WebhookUnauthorized WebhookOutcome = "unauthorized"
	WebhookMalformed    WebhookOutcome = "malformed"
	WebhookApproved     WebhookOutcome = "approved"
)

type WebhookVerification struct {
	Outcome WebhookOutcome
	OrderID int64
}

func CreateCheckoutURL(orderID int64) string {
	return fmt.Sprintf("https://pawpal.example/checkout?orderId=%d", orderID)
}

func VerifyWebhook(providedKey, expectedKey []byte, payload any) WebhookVerification {
	payloadRecord, payloadValid := payload.(map[string]any)
	if !payloadValid {
		return WebhookVerification{
			Outcome: WebhookMalformed,
		}
	}
	orderID, hasOrderID := payloadRecord["orderId"].(float64)
	if !hasOrderID || orderID < 0 || payloadRecord["status"] != "approved" {
		return WebhookVerification{
			Outcome: WebhookMalformed,
		}
	}
	//orderID, hasStatus := payloadRecord["status"].(string)

	if subtle.ConstantTimeCompare(providedKey, expectedKey) == 0 {
		return WebhookVerification{
			Outcome: WebhookUnauthorized,
		}
	}

	return WebhookVerification{Outcome: WebhookApproved, OrderID: int64(orderID)}
}
