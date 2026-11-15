#!/usr/bin/env bash
# Starts a local Anvil chain with everything the x402 payment demo needs and
# writes run/deployment.json:
#   - the SAGE 0.11.0 chain Registry (sage-contracts deploy-chain-registry.mjs)
#   - Permit2 at its canonical address and the x402 exact proxy at the address
#     the x402 Go SDK hard-codes (both placed with anvil_setCode)
#   - DemoUSD, a delegated account for model B, and a funded agent account for model A
#
# Usage: scripts/local-chain.sh [port]
# Needs anvil, cast and forge (Foundry 1.9), node, and a sage-contracts checkout
# with npm dependencies (SAGE_CONTRACTS_DIR, default ../sage-contracts).
# All keys are the public Anvil test accounts. Nothing here holds real value.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${1:-8545}"
RPC="http://127.0.0.1:${PORT}"
RUN="${ROOT}/run"
SAGE_CONTRACTS_DIR="${SAGE_CONTRACTS_DIR:-${ROOT}/../sage-contracts}"
MNEMONIC="test test test test test test test test test test test junk"
PERMIT2=0x000000000022D473030F116dDEE9F6B43aC78BA3
PROXY=0x402085c248EeA27D92E8b30b2C58ed07f9E20001

key() { cast wallet private-key --mnemonic "$MNEMONIC" --mnemonic-index "$1"; }
addr() { cast wallet address --private-key "$1"; }
DEPLOYER_KEY=$(key 0); USER_KEY=$(key 4); AGENT_PAY_KEY=$(key 5); AGENT_ACCOUNT_KEY=$(key 6)
USER=$(addr "$USER_KEY"); AGENT_PAY=$(addr "$AGENT_PAY_KEY"); AGENT_ACCOUNT=$(addr "$AGENT_ACCOUNT_KEY")
MERCHANT=$(addr "$(key 7)"); FACILITATOR=$(addr "$(key 8)")

mkdir -p "$RUN"
if [ -e "$RUN/deployment.json" ]; then
  echo "run/deployment.json exists; remove run/ to start a fresh chain" >&2
  exit 1
fi
if ! cast chain-id --rpc-url "$RPC" >/dev/null 2>&1; then
  anvil --port "$PORT" --chain-id 31337 --silent >"$RUN/anvil.log" 2>&1 &
  echo $! >"$RUN/anvil.pid"
  for _ in $(seq 1 50); do cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.2; done
fi
[ "$(cast chain-id --rpc-url "$RPC")" = 31337 ] || { echo "chain at $RPC is not 31337" >&2; exit 1; }

create() { # contract, then constructor arguments
  local contract=$1; shift
  (cd "$ROOT/contracts" && forge create "$contract" --rpc-url "$RPC" --private-key "${KEY:-$DEPLOYER_KEY}" \
    --broadcast --json ${1:+--constructor-args "$@"}) | python3 -c 'import json,sys;print(json.load(sys.stdin)["deployedTo"])'
}

# Permit2 caches its EIP-712 domain, address included, when the deploy chain
# ID equals the current one. Deploying it under chain ID 1 makes
# DOMAIN_SEPARATOR() recompute from the live chain ID and address, so its code
# works when copied to the canonical address on chain 31337.
cast rpc anvil_setChainId 1 --rpc-url "$RPC" >/dev/null
staging=$(create lib/permit2/src/Permit2.sol:Permit2)
cast rpc anvil_setChainId 31337 --rpc-url "$RPC" >/dev/null
cast rpc anvil_setCode "$PERMIT2" "$(cast code "$staging" --rpc-url "$RPC")" --rpc-url "$RPC" >/dev/null
expected=$(cast keccak "$(cast abi-encode 'f(bytes32,bytes32,uint256,address)' \
  "$(cast keccak 'EIP712Domain(string name,uint256 chainId,address verifyingContract)')" \
  "$(cast keccak Permit2)" 31337 "$PERMIT2")")
[ "$(cast call "$PERMIT2" 'DOMAIN_SEPARATOR()(bytes32)' --rpc-url "$RPC")" = "$expected" ] ||
  { echo "Permit2 domain separator mismatch" >&2; exit 1; }

staging=$(create src/vendor/x402/x402ExactPermit2Proxy.sol:x402ExactPermit2Proxy "$PERMIT2")
cast rpc anvil_setCode "$PROXY" "$(cast code "$staging" --rpc-url "$RPC")" --rpc-url "$RPC" >/dev/null
[ "$(cast call "$PROXY" 'PERMIT2()(address)' --rpc-url "$RPC")" = "$PERMIT2" ] ||
  { echo "proxy does not point to Permit2" >&2; exit 1; }

DEPLOYER=$(addr "$DEPLOYER_KEY")
TOKEN=$(create src/DemoUSD.sol:DemoUSD "$DEPLOYER")
send() { cast send "$@" --rpc-url "$RPC" >/dev/null; }
send --private-key "$DEPLOYER_KEY" "$TOKEN" 'mint(address,uint256)' "$USER" 1000000000

# The Registry deploys with the same deployer, so its address is deterministic
# only on a fresh chain; the record below is the source of truth.
(cd "$SAGE_CONTRACTS_DIR/ethereum" &&
  { [ -f component-tests/chain-registry/evidence/soljson.cjs ] || python3 component-tests/chain-registry/prepare.py; } &&
  node scripts/deploy-chain-registry.mjs --rpc "$RPC" --network anvil --out "$RUN/registry.json") >/dev/null
REGISTRY_ID=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["registry_id"])' "$RUN/registry.json")
DID="did:sage:${REGISTRY_ID}:payment-agent"

# Model A: the user moves 50 DUSD to an account the agent controls.
send --private-key "$USER_KEY" "$TOKEN" 'transfer(address,uint256)' "$AGENT_ACCOUNT" 50000000

# Model B: the user keeps 500 DUSD in a delegated account and lets the agent
# payment key spend at most 10 DUSD per payment, 25 DUSD in total, to the merchant only.
ACCOUNT=$(KEY=$USER_KEY create src/SageDelegatedAccount.sol:SageDelegatedAccount "$USER" "$PERMIT2" "$PROXY")
send --private-key "$USER_KEY" "$TOKEN" 'transfer(address,uint256)' "$ACCOUNT" 500000000
EXPIRES=$(( $(cast block latest -f timestamp --rpc-url "$RPC") + 86400 ))
send --private-key "$USER_KEY" "$ACCOUNT" 'delegate(address,string,address,uint256,uint64,address[])' \
  "$AGENT_PAY" "$DID" "$TOKEN" 10000000 "$EXPIRES" "[$MERCHANT]"
send --private-key "$USER_KEY" "$ACCOUNT" 'setBudget(address,uint256)' "$TOKEN" 25000000

python3 - "$RUN" <<EOF
import json, sys
json.dump({
  "scope": "Local Anvil demo; no real value",
  "rpc": "$RPC", "chain_id": 31337, "network": "eip155:31337",
  "registry_record": "run/registry.json", "registry_id": "$REGISTRY_ID", "agent_did": "$DID",
  "permit2": "$PERMIT2", "x402_exact_permit2_proxy": "$PROXY",
  "token": {"address": "$TOKEN", "name": "Demo USD", "version": "1", "decimals": 6},
  "accounts": {"user": "$USER", "agent_payment_key": "$AGENT_PAY", "agent_account": "$AGENT_ACCOUNT",
               "merchant": "$MERCHANT", "facilitator": "$FACILITATOR"},
  "model_a": {"payer": "$AGENT_ACCOUNT", "funded": "50000000"},
  "model_b": {"delegated_account": "$ACCOUNT", "per_payment_cap": "10000000", "budget": "25000000",
              "expires": $EXPIRES, "pay_to": ["$MERCHANT"]},
}, open(sys.argv[1] + "/deployment.json", "w"), indent=2)
EOF
echo "deployment written to run/deployment.json"
