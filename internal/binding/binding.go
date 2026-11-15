// Package binding is the SAGE x402 binding of this demo (decision D21). Both
// the payment agent and the resource server are SAGE 0.11.0 agents, and every
// x402 message travels inside a SAGE-signed envelope:
//
//   - the 402 quote is a SAGE-signed response, so payTo and amount cannot be
//     replaced on the way;
//   - the payment payload is part of the SAGE-signed request, so it cannot be
//     stripped, replaced or moved to another request;
//   - the payer is bound to the requesting DID: for a delegated account
//     (model B) the account's on-chain delegation must name that DID; for an
//     agent account (model A) the payer key signs a statement naming that DID
//     (EIP-191). A payer address that only the DID asserts is not enough,
//     because anyone can assert any address.
//
// The standard PAYMENT-* headers are not used: the signed envelope carries
// the same x402 objects.
package binding

import (
	"encoding/json"

	x402types "github.com/x402-foundation/x402/go/v2/types"
)

// Request is the payload of a SAGE request to the resource server.
type Request struct {
	Action   string `json:"action"`             // "quote" or "pay"
	Resource string `json:"resource"`           // what the agent wants
	QuoteID  string `json:"quote_id,omitempty"` // for "pay"
	Payer    string `json:"payer,omitempty"`    // address the requesting DID pays from
	// PayerBinding is the payer key's EIP-191 signature over BindingStatement(did).
	PayerBinding string                    `json:"payer_binding,omitempty"`
	Payment      *x402types.PaymentPayload `json:"payment,omitempty"` // for "pay"
}

// Quote is the data of the signed 402 response.
type Quote struct {
	QuoteID      string                        `json:"quote_id"`
	Requirements x402types.PaymentRequirements `json:"requirements"`
}

// Receipt is the data of the signed 200 response after settlement.
type Receipt struct {
	Resource    string `json:"resource"`
	Payer       string `json:"payer"`
	Transaction string `json:"transaction"`
}

// BindingStatement is what a model A payer key signs to name the DID it pays for.
func BindingStatement(did string) []byte {
	return []byte("SAGE x402 payer binding\nDID: " + did)
}

func canonical(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}
