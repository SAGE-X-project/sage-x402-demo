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

## Status

Under construction. See the SAGE work checklist for the plan.
