package binding

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/sage-x-project/sage/pkg/agent/wire011"
	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	evmfacilitator "github.com/x402-foundation/x402/go/v2/mechanisms/evm/exact/facilitator"
	x402types "github.com/x402-foundation/x402/go/v2/types"

	"github.com/sage-x-project/sage-x402-demo/internal/chain"
	"github.com/sage-x-project/sage-x402-demo/internal/trace"
)

// Prices maps a resource to its price and recipient.
type Price struct {
	Amount, PayTo, Method string
}

// Server is the resource server: a SAGE agent that sells resources for x402 payments.
type Server struct {
	Signer      *wire011.Signer
	Facilitator *evmfacilitator.ExactEvmScheme
	Chain       *chain.FacilitatorSigner
	Network     string
	Token       struct{ Address, Name, Version string }
	Prices      map[string]Price
	Trace       trace.Sink
	Now         func() time.Time

	mu     sync.Mutex
	quotes map[string]*quote
}

type quote struct {
	requester    string
	requirements x402types.PaymentRequirements
	expires      time.Time
	used         bool
}

// Handler answers verified requests. Mount it behind a wire011.Gate with a
// nil AllowUnprotected policy: an unprotected request never reaches it.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := wire011.ProtectionFrom(r.Context())
		if !p.Protected {
			http.Error(w, "authentication failed", http.StatusUnauthorized)
			return
		}
		var req Request
		if err := json.Unmarshal(p.Request.Payload, &req); err != nil {
			s.reply(w, p.Request, http.StatusBadRequest, false, nil, "operation_failed", "bad request: "+err.Error())
			return
		}
		switch req.Action {
		case "quote":
			s.quote(w, p.Request, req)
		case "pay":
			s.pay(r.Context(), w, p.Request, req)
		default:
			s.reply(w, p.Request, http.StatusBadRequest, false, nil, "operation_failed", "unknown action")
		}
	})
}

func (s *Server) quote(w http.ResponseWriter, v *wire011.VerifiedRequest, req Request) {
	price, ok := s.Prices[req.Resource]
	if !ok {
		s.reply(w, v, http.StatusNotFound, false, nil, "operation_failed", "unknown resource")
		return
	}
	id := randomID()
	q := &quote{requester: v.Envelope.DID, expires: s.Now().Add(5 * time.Minute), requirements: x402types.PaymentRequirements{
		Scheme: "exact", Network: s.Network, Asset: s.Token.Address, Amount: price.Amount, PayTo: price.PayTo,
		MaxTimeoutSeconds: 300, Extra: map[string]any{"name": s.Token.Name, "version": s.Token.Version,
			"assetTransferMethod": price.Method}}}
	s.mu.Lock()
	if s.quotes == nil {
		s.quotes = map[string]*quote{}
	}
	s.quotes[id] = q
	s.mu.Unlock()
	data, _ := json.Marshal(Quote{QuoteID: id, Requirements: q.requirements})
	s.emit(v, "x402.quote.signed", v.Envelope.DID, "issued", "", trace.Digest(q.requirements))
	s.reply(w, v, http.StatusPaymentRequired, false, data, "policy_denied", "")
}

func (s *Server) pay(ctx context.Context, w http.ResponseWriter, v *wire011.VerifiedRequest, req Request) {
	refuse := func(reason string) {
		s.emit(v, "x402.payment.refused", v.Envelope.DID, "refused", reason, "")
		s.reply(w, v, http.StatusPaymentRequired, false, nil, "policy_denied", reason)
	}
	s.mu.Lock()
	q := s.quotes[req.QuoteID]
	switch {
	case q == nil:
		s.mu.Unlock()
		refuse("unknown quote")
		return
	case q.used:
		s.mu.Unlock()
		refuse("quote already used")
		return
	case q.requester != v.Envelope.DID:
		s.mu.Unlock()
		refuse("quote belongs to another DID")
		return
	case !s.Now().Before(q.expires):
		s.mu.Unlock()
		refuse("quote expired")
		return
	}
	q.used = true // one attempt per quote, successful or not
	s.mu.Unlock()
	if req.Payment == nil || canonical(req.Payment.Accepted) != canonical(q.requirements) {
		refuse("payment does not accept the signed quote")
		return
	}
	payer, err := s.boundPayer(ctx, v.Envelope.DID, req)
	if err != nil {
		refuse("payer binding: " + err.Error())
		return
	}
	verify, err := s.Facilitator.Verify(ctx, *req.Payment, q.requirements, nil)
	if err != nil || !verify.IsValid {
		reason := "facilitator verify"
		if err == nil {
			reason += ": " + verify.InvalidReason
		}
		refuse(reason)
		return
	}
	settled, err := s.Facilitator.Settle(ctx, *req.Payment, q.requirements, nil)
	if err != nil || !settled.Success {
		refuse("facilitator settle")
		return
	}
	s.emit(v, "x402.payment.settled", payer, "settled", "", settled.Transaction)
	data, _ := json.Marshal(Receipt{Resource: req.Resource, Payer: payer, Transaction: settled.Transaction})
	s.reply(w, v, http.StatusOK, true, data, "", "")
}

// boundPayer returns the paying address only if the requesting DID controls it.
func (s *Server) boundPayer(ctx context.Context, did string, req Request) (string, error) {
	payload := req.Payment.Payload
	switch {
	case evm.IsPermit2Payload(payload):
		parsed, err := evm.Permit2PayloadFromMap(payload)
		if err != nil {
			return "", err
		}
		account := parsed.Permit2Authorization.From
		key, err := delegatedKey(common.FromHex(parsed.Signature))
		if err != nil {
			return "", err
		}
		out, err := s.Chain.ReadContract(ctx, account, delegationABI, "delegation", key)
		if err != nil {
			return "", fmt.Errorf("read delegation: %w", err)
		}
		values, ok := out.([]any)
		if !ok || len(values) == 0 {
			return "", fmt.Errorf("unexpected delegation result")
		}
		d, ok := abi.ConvertType(values[0], new(delegationView)).(*delegationView)
		if !ok {
			return "", fmt.Errorf("unexpected delegation shape %T", values[0])
		}
		if !d.Active || d.Did != did {
			return "", fmt.Errorf("delegation of %s names %q, not the requesting DID", key.Hex(), d.Did)
		}
		return account, nil
	default:
		parsed, err := evm.PayloadFromMap(payload)
		if err != nil {
			return "", err
		}
		signer, err := recoverPersonal(BindingStatement(did), common.FromHex(req.PayerBinding))
		if err != nil {
			return "", fmt.Errorf("payer binding signature: %w", err)
		}
		if !strings.EqualFold(signer.Hex(), parsed.Authorization.From) {
			return "", fmt.Errorf("payer %s did not bind itself to the requesting DID", parsed.Authorization.From)
		}
		return parsed.Authorization.From, nil
	}
}

// delegatedKey reads the payment key from the account signature layout
// abi.encode(PaymentAuthorization, key || ecdsa).
func delegatedKey(signature []byte) (common.Address, error) {
	values, err := delegatedSignatureArgs.Unpack(signature)
	if err != nil || len(values) != 2 {
		return common.Address{}, fmt.Errorf("account signature layout")
	}
	inner, ok := values[1].([]byte)
	if !ok || len(inner) != 85 {
		return common.Address{}, fmt.Errorf("agent signature layout")
	}
	return common.BytesToAddress(inner[:20]), nil
}

type delegationView struct {
	Did           string
	Token         common.Address
	PerPaymentCap *big.Int
	Expires       uint64
	Epoch         uint64
	Active        bool
}

var delegationABI = []byte(`[{"type":"function","name":"delegation","stateMutability":"view",
	"inputs":[{"name":"key","type":"address"}],
	"outputs":[{"name":"","type":"tuple","components":[{"name":"did","type":"string"},{"name":"token","type":"address"},
	{"name":"perPaymentCap","type":"uint256"},{"name":"expires","type":"uint64"},{"name":"epoch","type":"uint64"},
	{"name":"active","type":"bool"}]},{"name":"payTos","type":"address[]"}]}]`)

var delegatedSignatureArgs = func() abi.Arguments {
	parsed, err := abi.JSON(strings.NewReader(`[{"type":"function","name":"f","inputs":[{"name":"p","type":"tuple","components":[
		{"name":"token","type":"address"},{"name":"amount","type":"uint256"},{"name":"spender","type":"address"},
		{"name":"nonce","type":"uint256"},{"name":"deadline","type":"uint256"},{"name":"to","type":"address"},
		{"name":"validAfter","type":"uint256"}]},{"name":"s","type":"bytes"}]}]`))
	if err != nil {
		panic(err)
	}
	return parsed.Methods["f"].Inputs
}()

func (s *Server) reply(w http.ResponseWriter, v *wire011.VerifiedRequest, status int, success bool, data []byte, code, reason string) {
	if reason != "" {
		s.emit(v, "x402.reply", v.Envelope.DID, code, reason, "")
	}
	resp, err := s.Signer.SignResponse(v, status, success, data, code)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = wire011.WriteResponse(w, resp)
}

func (s *Server) emit(v *wire011.VerifiedRequest, boundary, actor, decision, reason, digest string) {
	if s.Trace == nil {
		return
	}
	s.Trace.Emit(trace.Event{Correlation: v.Envelope.ID, Boundary: boundary, ActorBefore: v.Envelope.DID,
		ActorAfter: actor, Decision: decision, Reason: reason, DigestOut: digest})
}

func recoverPersonal(message, signature []byte) (common.Address, error) {
	if len(signature) != 65 {
		return common.Address{}, fmt.Errorf("length %d", len(signature))
	}
	sig := append([]byte(nil), signature...)
	if sig[64] >= 27 {
		sig[64] -= 27
	}
	pub, err := crypto.SigToPub(accounts.TextHash(message), sig)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*pub), nil
}

func randomID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
