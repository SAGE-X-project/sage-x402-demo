// Command settle-scenarios pays a local x402 resource with the x402 Go SDK on
// the chain prepared by scripts/local-chain.sh, for both payment models, and
// checks that each refusal is refused for the expected reason. Every boundary
// where payment data or the acting party changes is written to a JSONL trace.
//
// Usage: go run ./cmd/settle-scenarios -deployment run/deployment.json -trace run/settle-trace.jsonl
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	x402 "github.com/x402-foundation/x402/go/v2"
	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
	evmclient "github.com/x402-foundation/x402/go/v2/mechanisms/evm/exact/client"
	evmfacilitator "github.com/x402-foundation/x402/go/v2/mechanisms/evm/exact/facilitator"
	evmsigners "github.com/x402-foundation/x402/go/v2/signers/evm"
	x402types "github.com/x402-foundation/x402/go/v2/types"

	"github.com/sage-x-project/sage-x402-demo/internal/chain"
	"github.com/sage-x-project/sage-x402-demo/internal/delegation"
	"github.com/sage-x-project/sage-x402-demo/internal/payer"
	"github.com/sage-x-project/sage-x402-demo/internal/trace"
)

// Public Anvil test accounts (mnemonic "test ... junk"); they hold no real value.
const (
	userKey         = "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a" // index 4
	agentPayKey     = "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba" // index 5
	agentAccountKey = "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e" // index 6
	facilitatorKey  = "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97" // index 8
)

type deployment struct {
	RPC     string `json:"rpc"`
	Network string `json:"network"`
	DID     string `json:"agent_did"`
	Token   struct {
		Address string `json:"address"`
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"token"`
	Accounts struct {
		Merchant     string `json:"merchant"`
		AgentAccount string `json:"agent_account"`
		User         string `json:"user"`
		AgentPayKey  string `json:"agent_payment_key"`
	} `json:"accounts"`
	ModelB struct {
		Account string   `json:"delegated_account"`
		Cap     string   `json:"per_payment_cap"`
		Budget  string   `json:"budget"`
		PayTo   []string `json:"pay_to"`
	} `json:"model_b"`
}

type runner struct {
	ctx         context.Context
	d           deployment
	facilitator *evmfacilitator.ExactEvmScheme
	signer      *chain.FacilitatorSigner
	sink        trace.Sink
	results     []result
}

type result struct {
	Name, Expected, Observed string
	Pass                     bool
}

func main() {
	deploymentPath := flag.String("deployment", "run/deployment.json", "deployment record from scripts/local-chain.sh")
	tracePath := flag.String("trace", "run/settle-trace.jsonl", "JSONL trace to create")
	flag.Parse()
	if err := run(*deploymentPath, *tracePath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(deploymentPath, tracePath string) error {
	raw, err := os.ReadFile(deploymentPath)
	if err != nil {
		return err
	}
	var d deployment
	if err := json.Unmarshal(raw, &d); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	signer, err := chain.NewFacilitatorSigner(ctx, d.RPC, facilitatorKey, 31337)
	if err != nil {
		return err
	}
	defer signer.Close()
	sink, err := trace.Open(tracePath)
	if err != nil {
		return err
	}
	defer sink.Close()
	r := &runner{ctx: ctx, d: d, signer: signer, sink: sink,
		facilitator: evmfacilitator.NewExactEvmScheme(signer, &evmfacilitator.ExactEvmSchemeConfig{SimulateInSettle: true})}

	modelA, err := evmsigners.NewClientSignerFromPrivateKey(agentAccountKey)
	if err != nil {
		return err
	}
	modelB, err := payer.NewDelegatedSigner(d.ModelB.Account, agentPayKey, signer.Client())
	if err != nil {
		return err
	}
	merchant, other := d.Accounts.Merchant, "0x0000000000000000000000000000000000007e57"

	// Model A: EIP-3009 from the account the user funded for the agent.
	paid := r.pay("A1 model A pays 2 DUSD", modelA, r.requirements("2000000", merchant, "eip3009"), "")
	r.replay("A2 model A authorization replayed", paid)
	r.swapPayTo("A3 model A payTo swapped after signing", modelA, merchant, other, "eip3009")

	// Model B: Permit2 from the user's delegated account, signed by the agent payment key.
	// Apply the deployment's terms first: another program may have changed them.
	if err := r.delegateFromDeployment(); err != nil {
		return err
	}
	r.pay("B1 model B pays 4 DUSD", modelB, r.requirements("4000000", merchant, "permit2"), "")
	r.pay("B2 model B over the per-payment cap", modelB, r.requirements("11000000", merchant, "permit2"), "acl")
	r.pay("B3 model B recipient outside the ACL", modelB, r.requirements("1000000", other, "permit2"), "acl")
	r.pay("B4 model B pays 10 DUSD", modelB, r.requirements("10000000", merchant, "permit2"), "")
	r.pay("B5 model B pays 10 DUSD", modelB, r.requirements("10000000", merchant, "permit2"), "")
	r.pay("B6 model B budget exhausted", modelB, r.requirements("10000000", merchant, "permit2"), "budget")
	if err := r.revokeDelegation(); err != nil {
		return err
	}
	r.pay("B7 model B after the user revokes the delegation", modelB, r.requirements("1000000", merchant, "permit2"), "acl")

	failed := 0
	for _, res := range r.results {
		status := "PASS"
		if !res.Pass {
			status, failed = "FAIL", failed+1
		}
		fmt.Printf("%s %s (expected %s, observed %s)\n", status, res.Name, res.Expected, res.Observed)
	}
	fmt.Printf("%d/%d scenarios passed; trace in %s\n", len(r.results)-failed, len(r.results), tracePath)
	if failed > 0 {
		return errors.New("scenario failures")
	}
	return nil
}

func (r *runner) requirements(amount, payTo, method string) x402types.PaymentRequirements {
	req := x402types.PaymentRequirements{Scheme: "exact", Network: r.d.Network, Asset: r.d.Token.Address, Amount: amount,
		PayTo: payTo, MaxTimeoutSeconds: 300,
		Extra: map[string]any{"name": r.d.Token.Name, "version": r.d.Token.Version, "assetTransferMethod": method}}
	r.sink.Emit(trace.Event{Correlation: amount + "/" + payTo, Boundary: "x402.requirements.issued", ActorAfter: "resource-server",
		DigestOut: trace.Digest(req), Decision: "issued", Detail: req})
	return req
}

// pay creates a payload as the agent, then verifies and settles it as the
// facilitator. wantRefusal is "" for success or "invalid" for a refusal.
func (r *runner) pay(name string, signer evm.ClientEvmSigner, req x402types.PaymentRequirements, wantRefusal string) *x402types.PaymentPayload {
	payload, err := evmclient.NewExactEvmScheme(signer, nil).CreatePaymentPayload(r.ctx, req, x402.PaymentPayloadContext{})
	if err != nil {
		r.record(name, outcome(wantRefusal), "client error: "+err.Error())
		return nil
	}
	payload.Accepted = req
	r.sink.Emit(trace.Event{Correlation: name, Boundary: "x402.payload.created", ActorBefore: "agent", ActorAfter: signer.Address(),
		DigestIn: trace.Digest(req), DigestOut: trace.Digest(payload.Payload), Decision: "signed"})
	observed := r.settle(name, payload, req)
	r.record(name, outcome(wantRefusal), observed)
	return &payload
}

func (r *runner) settle(name string, payload x402types.PaymentPayload, req x402types.PaymentRequirements) string {
	before, _ := r.signer.GetBalance(r.ctx, req.PayTo, r.d.Token.Address)
	verify, err := r.facilitator.Verify(r.ctx, payload, req, nil)
	reason := ""
	if err != nil {
		reason = err.Error()
	} else if !verify.IsValid {
		reason = verify.InvalidReason
	}
	cause, detail := r.permit2Cause(payload, req, reason)
	r.sink.Emit(trace.Event{Correlation: name, Boundary: "x402.facilitator.verify", ActorBefore: payload.Accepted.PayTo,
		ActorAfter: "facilitator", DigestIn: trace.Digest(payload.Payload), Decision: decision(reason == ""), Reason: reason,
		Detail: detail})
	if reason != "" {
		return "invalid(" + cause + "): " + reason
	}
	settled, err := r.facilitator.Settle(r.ctx, payload, req, nil)
	if err != nil || !settled.Success {
		if err == nil {
			err = errors.New(settled.ErrorReason)
		}
		r.sink.Emit(trace.Event{Correlation: name, Boundary: "x402.facilitator.settle", ActorAfter: "facilitator",
			Decision: "refused", Reason: err.Error()})
		return "invalid: settle " + err.Error()
	}
	after, _ := r.signer.GetBalance(r.ctx, req.PayTo, r.d.Token.Address)
	delta := new(big.Int).Sub(after, before)
	r.sink.Emit(trace.Event{Correlation: name, Boundary: "x402.facilitator.settle", ActorBefore: settled.Payer,
		ActorAfter: req.PayTo, Decision: "settled", Detail: map[string]string{"transaction": settled.Transaction,
			"payTo_delta": delta.String()}})
	if delta.String() != req.Amount {
		return "settled with wrong amount " + delta.String()
	}
	return "settled"
}

// permit2Cause asks the paying account and the token why a model B payment
// was refused, because the facilitator reports every Permit2 refusal as a
// failed simulation. "acl" means the delegated account rejected the agent
// signature; "budget" means it accepted it but the Permit2 allowance is short.
func (r *runner) permit2Cause(payload x402types.PaymentPayload, req x402types.PaymentRequirements, reason string) (string, any) {
	if reason == "" || !evm.IsPermit2Payload(payload.Payload) {
		return "other", nil
	}
	parsed, err := evm.Permit2PayloadFromMap(payload.Payload)
	if err != nil {
		return "other", map[string]string{"parse": err.Error()}
	}
	hash, err := evm.HashPermit2Authorization(parsed.Permit2Authorization, big.NewInt(31337))
	if err != nil {
		return "other", map[string]string{"hash": err.Error()}
	}
	var digest [32]byte
	copy(digest[:], hash)
	signature := common.FromHex(parsed.Signature)
	owner := parsed.Permit2Authorization.From
	magic, err := r.signer.ReadContract(r.ctx, owner, []byte(`[{"type":"function","name":"isValidSignature","stateMutability":"view",
		"inputs":[{"name":"h","type":"bytes32"},{"name":"s","type":"bytes"}],"outputs":[{"name":"","type":"bytes4"}]}]`),
		"isValidSignature", digest, signature)
	accepted := err == nil && magic == [4]byte{0x16, 0x26, 0xba, 0x7e}
	allowance, _ := r.signer.ReadContract(r.ctx, req.Asset, []byte(`[{"type":"function","name":"allowance","stateMutability":"view",
		"inputs":[{"name":"o","type":"address"},{"name":"s","type":"address"}],"outputs":[{"name":"","type":"uint256"}]}]`),
		"allowance", common.HexToAddress(owner), common.HexToAddress(evm.PERMIT2Address))
	amount, _ := new(big.Int).SetString(req.Amount, 10)
	detail := map[string]any{"account_signature_accepted": accepted, "permit2_allowance": fmt.Sprint(allowance), "amount": req.Amount}
	switch {
	case !accepted:
		return "acl", detail
	case allowance != nil && allowance.(*big.Int).Cmp(amount) < 0:
		return "budget", detail
	}
	return "other", detail
}

func (r *runner) replay(name string, payload *x402types.PaymentPayload) {
	if payload == nil {
		r.record(name, "invalid", "no payload to replay")
		return
	}
	r.record(name, "invalid", r.settle(name, *payload, payload.Accepted))
}

// swapPayTo signs for one recipient and presents requirements naming another,
// as a relay that rewrites an unsigned 402 response would.
func (r *runner) swapPayTo(name string, signer evm.ClientEvmSigner, signedFor, presented, method string) {
	signed := r.requirements("1000000", signedFor, method)
	payload, err := evmclient.NewExactEvmScheme(signer, nil).CreatePaymentPayload(r.ctx, signed, x402.PaymentPayloadContext{})
	if err != nil {
		r.record(name, "invalid", "client error: "+err.Error())
		return
	}
	swapped := signed
	swapped.PayTo = presented
	payload.Accepted = swapped
	r.record(name, "invalid", r.settle(name, payload, swapped))
}

func (r *runner) delegateFromDeployment() error {
	capAmount, ok1 := new(big.Int).SetString(r.d.ModelB.Cap, 10)
	budget, ok2 := new(big.Int).SetString(r.d.ModelB.Budget, 10)
	if !ok1 || !ok2 {
		return errors.New("deployment: model_b cap or budget")
	}
	return delegation.Apply(r.ctx, r.d.RPC, userKey, r.d.ModelB.Account, delegation.Terms{Key: r.d.Accounts.AgentPayKey, DID: r.d.DID,
		Token: r.d.Token.Address, Cap: capAmount, Budget: budget, TTL: 86400, PayTos: r.d.ModelB.PayTo})
}

func (r *runner) revokeDelegation() error {
	key, err := crypto.HexToECDSA(strings.TrimPrefix(userKey, "0x"))
	if err != nil {
		return err
	}
	data := append(crypto.Keccak256([]byte("revoke(address)"))[:4], common.LeftPadBytes(common.HexToAddress(r.d.Accounts.AgentPayKey).Bytes(), 32)...)
	to := common.HexToAddress(r.d.ModelB.Account)
	client := r.signer.Client()
	nonce, err := client.PendingNonceAt(r.ctx, crypto.PubkeyToAddress(key.PublicKey))
	if err != nil {
		return err
	}
	head, err := client.HeaderByNumber(r.ctx, nil)
	if err != nil {
		return err
	}
	tx, err := types.SignTx(types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(31337), Nonce: nonce, GasTipCap: big.NewInt(1),
		GasFeeCap: new(big.Int).Mul(head.BaseFee, big.NewInt(2)), Gas: 200_000, To: &to, Data: data}),
		types.LatestSignerForChainID(big.NewInt(31337)), key)
	if err != nil {
		return err
	}
	if err := client.SendTransaction(r.ctx, tx); err != nil {
		return err
	}
	receipt, err := r.signer.WaitForTransactionReceipt(r.ctx, tx.Hash().Hex())
	if err != nil || receipt.Status != 1 {
		return fmt.Errorf("revoke failed: %v", err)
	}
	r.sink.Emit(trace.Event{Correlation: "revoke", Boundary: "account.delegation.revoked", ActorBefore: r.d.Accounts.User,
		ActorAfter: r.d.ModelB.Account, Decision: "revoked", Detail: map[string]string{"key": r.d.Accounts.AgentPayKey,
			"transaction": tx.Hash().Hex()}})
	return nil
}

func (r *runner) record(name, expected, observed string) {
	pass := observed == "settled" && expected == "settled" ||
		expected == "invalid" && strings.HasPrefix(observed, "invalid") ||
		expected != "settled" && expected != "invalid" && strings.HasPrefix(observed, "invalid("+expected+")")
	r.results = append(r.results, result{name, expected, observed, pass})
}

func outcome(wantRefusal string) string {
	if wantRefusal == "" {
		return "settled"
	}
	return wantRefusal
}

func decision(ok bool) string {
	if ok {
		return "valid"
	}
	return "invalid"
}
