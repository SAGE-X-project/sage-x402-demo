# sage-x402-demo

A demo of an x402 payment agent built on SAGE. It is not part of the SAGE
protocol: payment does not decide trust in SAGE (sage-spec `charter.md`). The
SAGE Registry contracts stay in
[sage-contracts](https://github.com/SAGE-X-project/sage-contracts); this
repository only adds what the payment demo needs.

## Scope

- **Two ways for an agent to pay.**
  - Model A: the user transfers funds to an account the agent controls, and the agent pays from it with EIP-3009.
  - Model B: the user keeps funds in a delegated account. The agent's payment key may authorize payments through the x402 Permit2 path, but only within a per-payment cap, allowed recipients, an expiry, and a total budget enforced by the Permit2 allowance. The user can revoke the delegation at any time.
- **Local first.** Everything runs on a local Anvil chain: the SAGE Registry from sage-contracts, a test token, Permit2, an x402 facilitator built on the coinbase/x402 Go SDK, a resource server and the payment agent.
- **Message integrity.** Between SAGE agents, requests and responses use the SAGE 0.11.0 message signatures, and the x402 payment headers are bound to them. Peers without SAGE are handled as unprotected and may not pay.
- **Debugging.** Every point where payment data or the acting party changes leaves a trace record.

Nothing here holds real value. Keys are public Anvil test accounts.

## Run locally

Needs Foundry 1.9 (`anvil`, `cast`, `forge`), Go 1.26 and a sibling
`sage-contracts` checkout with `npm ci` done in `ethereum/`.

```bash
git submodule update --init --recursive
scripts/local-chain.sh            # anvil on :8545, writes run/deployment.json
go run ./cmd/binding-scenarios    # 8 SAGE x402 binding scenarios, trace in run/binding-trace.jsonl
go run ./cmd/settle-scenarios     # 10 payment scenarios, trace in run/settle-trace.jsonl
```

### SAGE x402 binding

`binding-scenarios` runs a payment agent and a resource server that are both
SAGE 0.11.0 agents registered in the chain Registry (`sage` `wire011`, keys
read from the Registry on every message):

- the 402 quote is a SAGE-signed response, so `payTo` and the amount cannot be replaced;
- the x402 payment payload travels inside the SAGE-signed request, so it cannot be stripped, changed or moved;
- each quote belongs to one requesting DID and can be used once;
- the payer is bound to the requesting DID. For model B the delegated account's on-chain delegation must name that DID. For model A the payer key signs `SAGE x402 payer binding\nDID: <did>` (EIP-191): a payer address that only the DID asserts would let any agent claim someone else's account.

The attacks it mounts and expects to be refused: a relay rewriting `payTo` in
the quote, a relay changing the amount in the signed payment, another
registered agent submitting the agent's intercepted delegated payment or
claiming its model A account, paying one quote twice, and sending the payment
without SAGE.

`local-chain.sh` deploys the SAGE Registry, places Permit2 and the x402 exact
proxy at the addresses the x402 Go SDK `go/v2.29.0` hard-codes, deploys the
demo token and a delegated account, and funds both models.
`settle-scenarios` pays with the SDK client and settles with the SDK
facilitator. For refused model B payments it also asks the account and the
token why, because the facilitator reports every Permit2 refusal as a failed
simulation.

## Status

Under construction. See the SAGE work checklist for the plan.
