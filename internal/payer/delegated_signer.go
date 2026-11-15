// Package payer holds the agent-side x402 signers.
package payer

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
)

// The account's PaymentAuthorization tuple, in contract field order.
const authorizationTuple = `{"name":"payment","type":"tuple","components":[
	{"name":"token","type":"address"},{"name":"amount","type":"uint256"},{"name":"spender","type":"address"},
	{"name":"nonce","type":"uint256"},{"name":"deadline","type":"uint256"},{"name":"to","type":"address"},
	{"name":"validAfter","type":"uint256"}]}`

// agentDigest is the account's view; encodeSignature only describes the
// abi.encode(PaymentAuthorization, bytes) layout of the signature.
var accountABI = mustABI(`[{"type":"function","name":"agentDigest","stateMutability":"view",
	"inputs":[` + authorizationTuple + `,{"name":"key","type":"address"}],"outputs":[{"name":"","type":"bytes32"}]},
	{"type":"function","name":"encodeSignature","stateMutability":"pure",
	"inputs":[` + authorizationTuple + `,{"name":"agentSignature","type":"bytes"}],"outputs":[]}]`)

var signatureArgs = accountABI.Methods["encodeSignature"].Inputs

// PaymentAuthorization mirrors SageDelegatedAccount.PaymentAuthorization.
type PaymentAuthorization struct {
	Token      common.Address
	Amount     *big.Int
	Spender    common.Address
	Nonce      *big.Int
	Deadline   *big.Int
	To         common.Address
	ValidAfter *big.Int
}

// DelegatedSigner is a ClientEvmSigner whose address is a SageDelegatedAccount.
// The SDK builds an ordinary Permit2 payment for that account; this signer
// turns the Permit2 typed data into the account-bound signature the account
// accepts: abi.encode(PaymentAuthorization, key || ecdsa(agentDigest)).
type DelegatedSigner struct {
	account common.Address
	key     *ecdsa.PrivateKey
	client  *ethclient.Client
}

var _ evm.ClientEvmSigner = (*DelegatedSigner)(nil)

func NewDelegatedSigner(account string, privateKeyHex string, client *ethclient.Client) (*DelegatedSigner, error) {
	key, err := crypto.HexToECDSA(strings.TrimPrefix(privateKeyHex, "0x"))
	if err != nil {
		return nil, fmt.Errorf("agent payment key: %w", err)
	}
	return &DelegatedSigner{account: common.HexToAddress(account), key: key, client: client}, nil
}

func (s *DelegatedSigner) Address() string { return s.account.Hex() }

// KeyAddress is the delegated payment key, not the paying account.
func (s *DelegatedSigner) KeyAddress() common.Address { return crypto.PubkeyToAddress(s.key.PublicKey) }

func (s *DelegatedSigner) SignTypedData(ctx context.Context, domain evm.TypedDataDomain,
	_ map[string][]evm.TypedDataField, primaryType string, message map[string]any) ([]byte, error) {
	if primaryType != "PermitWitnessTransferFrom" || domain.Name != "Permit2" ||
		!strings.EqualFold(domain.VerifyingContract, evm.PERMIT2Address) {
		return nil, errors.New("delegated account signs only x402 Permit2 payments")
	}
	payment, err := authorizationFromMessage(message)
	if err != nil {
		return nil, err
	}
	data, err := accountABI.Pack("agentDigest", payment, s.KeyAddress())
	if err != nil {
		return nil, err
	}
	result, err := s.client.CallContract(ctx, ethereum.CallMsg{To: &s.account, Data: data}, nil)
	if err != nil {
		return nil, fmt.Errorf("agentDigest: %w", err)
	}
	out, err := accountABI.Unpack("agentDigest", result)
	if err != nil {
		return nil, err
	}
	digest := out[0].([32]byte)
	signature, err := crypto.Sign(digest[:], s.key)
	if err != nil {
		return nil, err
	}
	signature[64] += 27
	return signatureArgs.Pack(payment, append(s.KeyAddress().Bytes(), signature...))
}

func authorizationFromMessage(message map[string]any) (PaymentAuthorization, error) {
	permitted, ok := message["permitted"].(map[string]any)
	witness, ok2 := message["witness"].(map[string]any)
	if !ok || !ok2 {
		return PaymentAuthorization{}, errors.New("unexpected Permit2 message shape")
	}
	values := map[string]*big.Int{}
	for name, raw := range map[string]any{"amount": permitted["amount"], "nonce": message["nonce"],
		"deadline": message["deadline"], "validAfter": witness["validAfter"]} {
		value, err := toBig(raw)
		if err != nil {
			return PaymentAuthorization{}, fmt.Errorf("%s: %w", name, err)
		}
		values[name] = value
	}
	return PaymentAuthorization{
		Token: common.HexToAddress(fmt.Sprint(permitted["token"])), Amount: values["amount"],
		Spender: common.HexToAddress(fmt.Sprint(message["spender"])), Nonce: values["nonce"],
		Deadline: values["deadline"], To: common.HexToAddress(fmt.Sprint(witness["to"])),
		ValidAfter: values["validAfter"],
	}, nil
}

func toBig(raw any) (*big.Int, error) {
	switch v := raw.(type) {
	case *big.Int:
		return new(big.Int).Set(v), nil
	case string:
		if n, ok := new(big.Int).SetString(v, 0); ok {
			return n, nil
		}
	}
	return nil, fmt.Errorf("not an integer: %v", raw)
}

func mustABI(text string) abi.ABI {
	parsed, err := abi.JSON(strings.NewReader(text))
	if err != nil {
		panic(err)
	}
	return parsed
}
