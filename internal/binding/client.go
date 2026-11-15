package binding

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/sage-x-project/sage/pkg/agent/wire011"
	x402 "github.com/x402-foundation/x402/go/v2"
	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	evmclient "github.com/x402-foundation/x402/go/v2/mechanisms/evm/exact/client"
)

// Agent is the payment agent: a SAGE agent that pays resource servers.
type Agent struct {
	Client *wire011.Client
	// Payer signs x402 authorizations; Address() is the paying account.
	Payer evm.ClientEvmSigner
	// BindPayer signs BindingStatement(did) with the payer key (model A). Nil
	// for a delegated account, whose delegation already names the DID.
	BindPayer func(statement []byte) ([]byte, error)
}

// ErrNotProtected means a step of the exchange did not come back SAGE-signed.
var ErrNotProtected = errors.New("binding: exchange was not protected")

// QuoteFor asks the server for a signed quote.
func (a *Agent) QuoteFor(ctx context.Context, serverDID, endpoint, resource string) (*Quote, error) {
	payload, _ := json.Marshal(Request{Action: "quote", Resource: resource})
	res, err := a.Client.Send(ctx, serverDID, endpoint, payload, wire011.RequestOptions{})
	if err != nil {
		return nil, err
	}
	if !res.Protected {
		return nil, ErrNotProtected
	}
	if res.Status != 402 || res.Response.Envelope.Error != "policy_denied" {
		return nil, fmt.Errorf("binding: expected a signed 402 quote, got %d", res.Status)
	}
	var q Quote
	if err := json.Unmarshal(res.Response.Data, &q); err != nil {
		return nil, fmt.Errorf("binding: quote: %w", err)
	}
	return &q, nil
}

// Authorize creates the x402 payment payload for a signed quote.
func (a *Agent) Authorize(ctx context.Context, q *Quote) (*Request, error) {
	payment, err := evmclient.NewExactEvmScheme(a.Payer, nil).CreatePaymentPayload(ctx, q.Requirements, x402.PaymentPayloadContext{})
	if err != nil {
		return nil, err
	}
	payment.Accepted = q.Requirements
	req := &Request{Action: "pay", QuoteID: q.QuoteID, Payer: a.Payer.Address(), Payment: &payment}
	if a.BindPayer != nil {
		sig, err := a.BindPayer(BindingStatement(a.Client.Signer.DID))
		if err != nil {
			return nil, err
		}
		req.PayerBinding = fmt.Sprintf("0x%x", sig)
	}
	return req, nil
}

// Pay sends a payment request and returns the signed receipt.
func (a *Agent) Pay(ctx context.Context, serverDID, endpoint string, req *Request) (*Receipt, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	res, err := a.Client.Send(ctx, serverDID, endpoint, payload, wire011.RequestOptions{})
	if err != nil {
		return nil, err
	}
	if !res.Protected {
		return nil, ErrNotProtected
	}
	if !res.Response.Envelope.Success {
		return nil, fmt.Errorf("binding: payment refused (%d %s)", res.Status, res.Response.Envelope.Error)
	}
	var receipt Receipt
	if err := json.Unmarshal(res.Response.Data, &receipt); err != nil {
		return nil, err
	}
	return &receipt, nil
}

// Buy quotes, authorizes and pays one resource.
func (a *Agent) Buy(ctx context.Context, serverDID, endpoint, resource string) (*Receipt, error) {
	q, err := a.QuoteFor(ctx, serverDID, endpoint, resource)
	if err != nil {
		return nil, err
	}
	req, err := a.Authorize(ctx, q)
	if err != nil {
		return nil, err
	}
	req.Resource = resource
	return a.Pay(ctx, serverDID, endpoint, req)
}
