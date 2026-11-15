// Package chain connects the x402 Go SDK to a local chain.
package chain

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/x402-foundation/x402/go/v2/mechanisms/evm"
)

// FacilitatorSigner implements the SDK's FacilitatorEvmSigner with one
// private key and one RPC endpoint. It is meant for a local development chain.
type FacilitatorSigner struct {
	client  *ethclient.Client
	key     *ecdsa.PrivateKey
	address common.Address
	chainID *big.Int
}

var _ evm.FacilitatorEvmSigner = (*FacilitatorSigner)(nil)

// NewFacilitatorSigner refuses any chain other than wantChainID.
func NewFacilitatorSigner(ctx context.Context, rpcURL, privateKeyHex string, wantChainID int64) (*FacilitatorSigner, error) {
	key, err := crypto.HexToECDSA(strings.TrimPrefix(privateKeyHex, "0x"))
	if err != nil {
		return nil, fmt.Errorf("facilitator key: %w", err)
	}
	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", rpcURL, err)
	}
	chainID, err := client.ChainID(ctx)
	if err != nil {
		client.Close()
		return nil, err
	}
	if chainID.Cmp(big.NewInt(wantChainID)) != 0 {
		client.Close()
		return nil, fmt.Errorf("chain %s is not %d", chainID, wantChainID)
	}
	return &FacilitatorSigner{client: client, key: key, address: crypto.PubkeyToAddress(key.PublicKey), chainID: chainID}, nil
}

func (s *FacilitatorSigner) Close()                    { s.client.Close() }
func (s *FacilitatorSigner) Client() *ethclient.Client { return s.client }
func (s *FacilitatorSigner) GetAddresses() []string    { return []string{s.address.Hex()} }
func (s *FacilitatorSigner) GetChainID(context.Context) (*big.Int, error) {
	return new(big.Int).Set(s.chainID), nil
}

func (s *FacilitatorSigner) GetCode(ctx context.Context, address string) ([]byte, error) {
	return s.client.CodeAt(ctx, common.HexToAddress(address), nil)
}

func (s *FacilitatorSigner) GetBalance(ctx context.Context, address, token string) (*big.Int, error) {
	if token == "" || common.HexToAddress(token) == (common.Address{}) {
		return s.client.BalanceAt(ctx, common.HexToAddress(address), nil)
	}
	out, err := s.ReadContract(ctx, token, []byte(`[{"type":"function","name":"balanceOf","stateMutability":"view",
		"inputs":[{"name":"a","type":"address"}],"outputs":[{"name":"","type":"uint256"}]}]`), "balanceOf", common.HexToAddress(address))
	if err != nil {
		return nil, err
	}
	balance, ok := out.(*big.Int)
	if !ok {
		return nil, errors.New("balanceOf returned a non-integer")
	}
	return balance, nil
}

// ReadContract mirrors the SDK's own RPC reader: one output is returned
// unwrapped, several as a slice.
func (s *FacilitatorSigner) ReadContract(ctx context.Context, address string, abiJSON []byte, method string, args ...any) (any, error) {
	parsed, err := abi.JSON(strings.NewReader(string(abiJSON)))
	if err != nil {
		return nil, err
	}
	data, err := parsed.Pack(method, args...)
	if err != nil {
		return nil, err
	}
	to := common.HexToAddress(address)
	result, err := s.client.CallContract(ctx, ethereum.CallMsg{From: s.address, To: &to, Data: data}, nil)
	if err != nil {
		return nil, err
	}
	outputs, err := parsed.Unpack(method, result)
	if err != nil {
		return nil, err
	}
	switch len(outputs) {
	case 0:
		return nil, nil
	case 1:
		return outputs[0], nil
	default:
		return outputs, nil
	}
}

func (s *FacilitatorSigner) VerifyTypedData(ctx context.Context, address string, domain evm.TypedDataDomain,
	types map[string][]evm.TypedDataField, primaryType string, message map[string]any, signature []byte) (bool, error) {
	hash, err := evm.HashTypedData(domain, types, primaryType, message)
	if err != nil {
		return false, err
	}
	var digest [32]byte
	copy(digest[:], hash)
	ok, _, err := evm.VerifyUniversalSignature(ctx, s, address, digest, signature, false)
	return ok, err
}

func (s *FacilitatorSigner) WriteContract(ctx context.Context, address string, abiJSON []byte, method string, dataSuffix []byte, args ...any) (string, error) {
	parsed, err := abi.JSON(strings.NewReader(string(abiJSON)))
	if err != nil {
		return "", err
	}
	data, err := parsed.Pack(method, args...)
	if err != nil {
		return "", err
	}
	return s.SendTransaction(ctx, address, append(data, dataSuffix...))
}

func (s *FacilitatorSigner) SendTransaction(ctx context.Context, to string, data []byte) (string, error) {
	target := common.HexToAddress(to)
	nonce, err := s.client.PendingNonceAt(ctx, s.address)
	if err != nil {
		return "", err
	}
	tip, err := s.client.SuggestGasTipCap(ctx)
	if err != nil {
		return "", err
	}
	head, err := s.client.HeaderByNumber(ctx, nil)
	if err != nil {
		return "", err
	}
	feeCap := new(big.Int).Add(new(big.Int).Mul(head.BaseFee, big.NewInt(2)), tip)
	gas, err := s.client.EstimateGas(ctx, ethereum.CallMsg{From: s.address, To: &target, Data: data})
	if err != nil {
		return "", fmt.Errorf("estimate gas: %w", err)
	}
	tx := types.NewTx(&types.DynamicFeeTx{ChainID: s.chainID, Nonce: nonce, GasTipCap: tip, GasFeeCap: feeCap,
		Gas: gas + gas/5, To: &target, Data: data})
	signed, err := types.SignTx(tx, types.LatestSignerForChainID(s.chainID), s.key)
	if err != nil {
		return "", err
	}
	if err := s.client.SendTransaction(ctx, signed); err != nil {
		return "", err
	}
	return signed.Hash().Hex(), nil
}

func (s *FacilitatorSigner) WaitForTransactionReceipt(ctx context.Context, txHash string) (*evm.TransactionReceipt, error) {
	hash := common.HexToHash(txHash)
	for {
		receipt, err := s.client.TransactionReceipt(ctx, hash)
		if err == nil {
			return &evm.TransactionReceipt{Status: receipt.Status, BlockNumber: receipt.BlockNumber.Uint64(), TxHash: txHash}, nil
		}
		if !errors.Is(err, ethereum.NotFound) {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
