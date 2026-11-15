// Command binding-scenarios runs the SAGE x402 binding between a payment
// agent and a resource server, both registered in the chain Registry on the
// local chain from scripts/local-chain.sh, and tries the attacks the binding
// must stop. Every decision is written to a JSONL trace.
//
// Usage: go run ./cmd/binding-scenarios -deployment run/deployment.json -trace run/binding-trace.jsonl
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/sage-x-project/sage/pkg/agent/registry011"
	"github.com/sage-x-project/sage/pkg/agent/wire011"
	"github.com/sage-x-project/sage/pkg/agent/wire011/registrykeys"
	evmfacilitator "github.com/x402-foundation/x402/go/v2/mechanisms/evm/exact/facilitator"
	evmsigners "github.com/x402-foundation/x402/go/v2/signers/evm"

	"github.com/sage-x-project/sage-x402-demo/internal/binding"
	"github.com/sage-x-project/sage-x402-demo/internal/chain"
	"github.com/sage-x-project/sage-x402-demo/internal/devtls"
	"github.com/sage-x-project/sage-x402-demo/internal/payer"
	"github.com/sage-x-project/sage-x402-demo/internal/trace"
)

// Public Anvil test accounts; they hold no real value.
const (
	agentPayKey     = "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba" // index 5
	agentAccountKey = "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e" // index 6
	facilitatorKey  = "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97" // index 8
	userKey         = "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a" // index 4
)

type deployment struct {
	RPC            string `json:"rpc"`
	Network        string `json:"network"`
	RegistryRecord string `json:"registry_record"`
	Token          struct{ Address, Name, Version string }
	Accounts       struct {
		Merchant string `json:"merchant"`
	} `json:"accounts"`
	ModelB struct {
		Account string `json:"delegated_account"`
	} `json:"model_b"`
}

type wall struct{}

func (wall) Now() (time.Time, error) { return time.Now(), nil }

// ownedSeed mirrors sage-contracts owned-fixtures.mjs: the disclosed public
// recipe the lifecycle scenarios use; sig-3 of key base B is recipe B+3.
func ownedSeed(index int) ed25519.PrivateKey {
	sum := sha256.Sum256([]byte(fmt.Sprintf("SAGE owned constructor unit public key recipe %d false", index)))
	return ed25519.NewKeyFromSeed(sum[:])
}

type result struct {
	name, want, got string
	pass            bool
}

func main() {
	deploymentPath := flag.String("deployment", "run/deployment.json", "deployment record")
	tracePath := flag.String("trace", "run/binding-trace.jsonl", "JSONL trace to create")
	flag.Parse()
	results, err := run(*deploymentPath, *tracePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	failed := 0
	for _, r := range results {
		status := "PASS"
		if !r.pass {
			status, failed = "FAIL", failed+1
		}
		fmt.Printf("%s %s (expected %s, observed %s)\n", status, r.name, r.want, r.got)
	}
	fmt.Printf("%d/%d binding scenarios passed; trace in %s\n", len(results)-failed, len(results), *tracePath)
	if failed > 0 {
		os.Exit(1)
	}
}

func run(deploymentPath, tracePath string) ([]result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var d deployment
	raw, err := os.ReadFile(deploymentPath)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, err
	}
	file, err := trace.Open(tracePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	sink := &lastRefusal{next: file}

	// Registry keys through the registry011 development profile.
	proxy, err := devtls.Start(d.RPC)
	if err != nil {
		return nil, err
	}
	defer proxy.Close()
	record, err := os.ReadFile(strings.Replace(deploymentPath, "deployment.json", "registry.json", 1))
	if err != nil {
		return nil, err
	}
	signer, err := chain.NewFacilitatorSigner(ctx, d.RPC, facilitatorKey, 31337)
	if err != nil {
		return nil, err
	}
	defer signer.Close()
	genesis, err := signer.Client().HeaderByNumber(ctx, bigZero())
	if err != nil {
		return nil, err
	}
	network, err := registry011.NewDevNetwork(registry011.DevNetworkConfig{Endpoint: proxy.URL, RootsPEM: proxy.RootPEM,
		GenesisHash: genesis.Hash().Hex(), DeploymentRecord: record})
	if err != nil {
		return nil, fmt.Errorf("dev network: %w", err)
	}
	rpc, err := registry011.NewReadRPC(network, registry011.RPCTransportLimits{RequestTimeout: 20 * time.Second, MaxBytes: 4 << 20, MaxDepth: 128})
	if err != nil {
		return nil, err
	}
	defer rpc.Close()
	keys := registrykeys.NewRegistryResolver(rpc, network, wall{})
	classifier := &registrykeys.Classifier{Source: keys.Source, RegistryID: network.RegistryID()}
	did := func(agent string) string { return "did:sage:" + network.RegistryID() + ":" + agent }
	identity := func(agent string, base int) *wire011.Signer {
		return &wire011.Signer{DID: did(agent), KID: did(agent) + "#sig-3", Key: ownedSeed(base + 3), Clock: wall{}, TTL: 120}
	}
	agentID, serverID, attackerID := identity("payment-agent", 100), identity("resource-server", 200), identity("attacker-agent", 300)
	tracer := traceAdapter{sink}
	replay := func() *wire011.MemoryReplay {
		return &wire011.MemoryReplay{Capacity: 4096, Clock: wall{}, Started: time.Now().Add(-wire011.Quarantine)}
	}

	// Resource server behind the default gate: no unprotected request reaches it.
	server := &binding.Server{Signer: serverID, Chain: signer, Network: d.Network, Trace: sink, Now: time.Now,
		Facilitator: evmfacilitator.NewExactEvmScheme(signer, &evmfacilitator.ExactEvmSchemeConfig{SimulateInSettle: true}),
		Prices: map[string]binding.Price{
			"/report-b": {Amount: "4000000", PayTo: d.Accounts.Merchant, Method: "permit2"},
			"/report-a": {Amount: "2000000", PayTo: d.Accounts.Merchant, Method: "eip3009"},
		}}
	server.Token.Address, server.Token.Name, server.Token.Version = d.Token.Address, d.Token.Name, d.Token.Version
	var endpoint string
	gate := &wire011.Gate{Receiver: &wire011.Receiver{DID: serverID.DID, Keys: keys, Replay: replay(), Clock: wall{}, Trace: tracer},
		TrustedTarget: func(*http.Request) string { return endpoint }, Next: server.Handler()}
	ts := httptest.NewTLSServer(gate)
	defer ts.Close()
	endpoint = ts.URL + "/x402"
	gate.Receiver.Endpoint = endpoint

	tamper := &tamperTransport{base: ts.Client().Transport}
	newClient := func(id *wire011.Signer) *wire011.Client {
		return &wire011.Client{Signer: id, Classifier: classifier, HTTP: &http.Client{Transport: tamper},
			Responses: &wire011.ResponseVerifier{Keys: keys, Replay: replay(), Clock: wall{}, Trace: tracer}}
	}
	delegated, err := payer.NewDelegatedSigner(d.ModelB.Account, agentPayKey, signer.Client())
	if err != nil {
		return nil, err
	}
	accountSigner, err := evmsigners.NewClientSignerFromPrivateKey(agentAccountKey)
	if err != nil {
		return nil, err
	}
	accountKey, _ := crypto.HexToECDSA(strings.TrimPrefix(agentAccountKey, "0x"))
	bindAccount := func(statement []byte) ([]byte, error) { return crypto.Sign(accountsTextHash(statement), accountKey) }
	// The user delegates afresh so this run does not depend on earlier runs:
	// 10 DUSD per payment, 50 DUSD in total, to the merchant only.
	if err := userDelegates(ctx, signer, d, delegated.KeyAddress().Hex(), agentID.DID); err != nil {
		return nil, fmt.Errorf("delegate: %w", err)
	}
	agentB := &binding.Agent{Client: newClient(agentID), Payer: delegated}
	agentA := &binding.Agent{Client: newClient(agentID), Payer: accountSigner, BindPayer: bindAccount}
	attacker := &binding.Agent{Client: newClient(attackerID), Payer: delegated}

	var results []result
	check := func(name, want string, err error) {
		got := "ok"
		if err != nil {
			got = err.Error()
		}
		pass := want == "ok" && err == nil || want != "ok" && err != nil && strings.Contains(got, want)
		results = append(results, result{name, want, got, pass})
		sink.Emit(trace.Event{Correlation: name, Boundary: "scenario.result", Decision: map[bool]string{true: "pass", false: "fail"}[pass], Reason: got})
	}

	_, err = agentB.Buy(ctx, serverID.DID, endpoint, "/report-b")
	check("P1 model B pays through the binding", "ok", err)
	_, err = agentA.Buy(ctx, serverID.DID, endpoint, "/report-a")
	check("P2 model A pays through the binding", "ok", err)

	// X1: a relay rewrites payTo in the 402 quote.
	tamper.rewriteResponse = rewriteEnvelope("data", d.Accounts.Merchant, "0x0000000000000000000000000000000000007E57")
	_, err = agentB.QuoteFor(ctx, serverID.DID, endpoint, "/report-b")
	tamper.rewriteResponse = nil
	err = tamper.applied(err)
	check("X1 relay rewrites payTo in the signed quote", "authentication failed", err)

	// X2: a relay changes the amount inside the signed payment request.
	q, err := agentB.QuoteFor(ctx, serverID.DID, endpoint, "/report-b")
	if err != nil {
		return nil, err
	}
	pay, err := agentB.Authorize(ctx, q)
	if err != nil {
		return nil, err
	}
	pay.Resource = "/report-b"
	tamper.rewriteRequest = rewriteEnvelope("payload", `"amount":"4000000"`, `"amount":"4000001"`)
	_, err = agentB.Pay(ctx, serverID.DID, endpoint, pay)
	tamper.rewriteRequest = nil
	err = tamper.applied(err)
	check("X2 relay changes the payment inside the signed request", "authentication failed", err)

	// X3: another registered agent submits the agent's intercepted delegated payment.
	stolen, err := attacker.QuoteFor(ctx, serverID.DID, endpoint, "/report-b")
	if err != nil {
		return nil, err
	}
	pay.QuoteID = stolen.QuoteID
	_, err = attacker.Pay(ctx, serverID.DID, endpoint, pay)
	check("X3 other DID uses the agent's delegated payment", "payment refused", sink.because("delegation of", err))

	// X4: another agent claims the agent's model A account without its payer binding.
	qa, err := agentA.QuoteFor(ctx, serverID.DID, endpoint, "/report-a")
	if err != nil {
		return nil, err
	}
	payA, err := agentA.Authorize(ctx, qa)
	if err != nil {
		return nil, err
	}
	qx, err := attacker.QuoteFor(ctx, serverID.DID, endpoint, "/report-a")
	if err != nil {
		return nil, err
	}
	payA.QuoteID, payA.Resource = qx.QuoteID, "/report-a"
	_, err = attacker.Pay(ctx, serverID.DID, endpoint, payA)
	check("X4 other DID reuses the agent's account binding", "payment refused", sink.because("did not bind itself", err))

	// X5: the same quote is paid twice.
	q5, err := agentB.QuoteFor(ctx, serverID.DID, endpoint, "/report-b")
	if err != nil {
		return nil, err
	}
	p5, err := agentB.Authorize(ctx, q5)
	if err != nil {
		return nil, err
	}
	p5.Resource = "/report-b"
	if _, err := agentB.Pay(ctx, serverID.DID, endpoint, p5); err != nil {
		return nil, fmt.Errorf("first payment of X5: %w", err)
	}
	_, err = agentB.Pay(ctx, serverID.DID, endpoint, p5)
	check("X5 the same quote is paid twice", "payment refused", sink.because("quote already used", err))

	// X6: the payment is sent without SAGE (headers stripped).
	body, _ := json.Marshal(p5)
	resp, err := ts.Client().Post(endpoint, "application/json", bytes.NewReader(body))
	if err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			err = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			err = errors.New("refused 401")
		}
	}
	check("X6 payment without SAGE reaches the gate", "refused 401", err)
	return results, nil
}

// tamperTransport plays a relay on the path that can rewrite bodies.
type tamperTransport struct {
	base                            http.RoundTripper
	rewriteRequest, rewriteResponse func([]byte) []byte
	changed                         bool
}

// applied turns a scenario whose tampering never matched into a failure, so
// an attack that was not actually mounted cannot pass as refused.
func (t *tamperTransport) applied(err error) error {
	defer func() { t.changed = false }()
	if !t.changed {
		return errors.New("tampering did not apply")
	}
	return err
}

// rewriteEnvelope decodes one base64url member of a SAGE envelope, replaces
// text in it and re-encodes it, leaving both signatures as they were.
func rewriteEnvelope(member, from, to string) func([]byte) []byte {
	return func(body []byte) []byte {
		var env map[string]any
		if json.Unmarshal(body, &env) != nil {
			return body
		}
		encoded, _ := env[member].(string)
		raw, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || !bytes.Contains(raw, []byte(from)) {
			return body
		}
		env[member] = base64.RawURLEncoding.EncodeToString(bytes.Replace(raw, []byte(from), []byte(to), 1))
		out, _ := json.Marshal(env)
		return out
	}
}

func (t *tamperTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.rewriteRequest != nil && r.Body != nil {
		raw, _ := io.ReadAll(r.Body)
		rewritten := t.rewriteRequest(raw)
		t.changed = t.changed || !bytes.Equal(rewritten, raw)
		raw = rewritten
		r.Body, r.ContentLength = io.NopCloser(bytes.NewReader(raw)), int64(len(raw))
	}
	resp, err := t.base.RoundTrip(r)
	if err != nil || t.rewriteResponse == nil {
		return resp, err
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	rewritten := t.rewriteResponse(raw)
	t.changed = t.changed || !bytes.Equal(rewritten, raw)
	raw = rewritten
	resp.Body, resp.ContentLength = io.NopCloser(bytes.NewReader(raw)), int64(len(raw))
	return resp, nil
}

type traceAdapter struct{ sink trace.Sink }

func (t traceAdapter) Trace(_ context.Context, e wire011.Event) {
	t.sink.Emit(trace.Event{Correlation: e.Correlation, Boundary: "wire011." + e.Stage, ActorBefore: e.From, ActorAfter: e.To,
		Decision: e.Decision, Reason: e.Reason})
}

func accountsTextHash(message []byte) []byte { return accounts.TextHash(message) }

func bigZero() *big.Int { return new(big.Int) }

var accountABI = mustABI(`[{"type":"function","name":"delegate","inputs":[{"name":"key","type":"address"},{"name":"did","type":"string"},
	{"name":"token","type":"address"},{"name":"cap","type":"uint256"},{"name":"expires","type":"uint64"},{"name":"payTos","type":"address[]"}],"outputs":[]},
	{"type":"function","name":"setBudget","inputs":[{"name":"token","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[]}]`)

func userDelegates(ctx context.Context, signer *chain.FacilitatorSigner, d deployment, key, did string) error {
	user, err := chain.NewFacilitatorSigner(ctx, d.RPC, userKey, 31337)
	if err != nil {
		return err
	}
	defer user.Close()
	head, err := user.Client().HeaderByNumber(ctx, nil)
	if err != nil {
		return err
	}
	calls := []struct {
		method string
		args   []any
	}{
		{"delegate", []any{common.HexToAddress(key), did, common.HexToAddress(d.Token.Address), big.NewInt(10_000_000),
			head.Time + 86400, []common.Address{common.HexToAddress(d.Accounts.Merchant)}}},
		{"setBudget", []any{common.HexToAddress(d.Token.Address), big.NewInt(50_000_000)}},
	}
	for _, c := range calls {
		data, err := accountABI.Pack(c.method, c.args...)
		if err != nil {
			return err
		}
		tx, err := user.SendTransaction(ctx, d.ModelB.Account, data)
		if err != nil {
			return err
		}
		receipt, err := user.WaitForTransactionReceipt(ctx, tx)
		if err != nil || receipt.Status != 1 {
			return fmt.Errorf("%s failed: %v", c.method, err)
		}
	}
	return nil
}

func mustABI(text string) abi.ABI {
	parsed, err := abi.JSON(strings.NewReader(text))
	if err != nil {
		panic(err)
	}
	return parsed
}

// lastRefusal remembers the server's last refusal reason so a scenario can
// require that a payment was refused for the expected cause.
type lastRefusal struct {
	next   trace.Sink
	reason string
}

func (l *lastRefusal) Emit(e trace.Event) {
	if e.Boundary == "x402.payment.refused" {
		l.reason = e.Reason
	}
	l.next.Emit(e)
}

func (l *lastRefusal) because(want string, err error) error {
	defer func() { l.reason = "" }()
	if err != nil && !strings.Contains(l.reason, want) {
		return fmt.Errorf("refused for %q, want %q", l.reason, want)
	}
	return err
}
