// Package delegation sets the model B delegation of a SageDelegatedAccount from
// the user's key. Each scenario program applies its own terms at start, so the
// programs do not depend on the order they run in or on each other's spending.
package delegation

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	"github.com/sage-x-project/sage-x402-demo/internal/chain"
)

// Terms are the delegation and budget the user grants the agent payment key.
type Terms struct {
	Key, DID, Token string
	Cap, Budget     *big.Int
	TTL             uint64 // seconds from the latest block
	PayTos          []string
}

var accountABI = func() abi.ABI {
	parsed, err := abi.JSON(strings.NewReader(`[{"type":"function","name":"delegate","inputs":[{"name":"key","type":"address"},{"name":"did","type":"string"},
	{"name":"token","type":"address"},{"name":"cap","type":"uint256"},{"name":"expires","type":"uint64"},{"name":"payTos","type":"address[]"}],"outputs":[]},
	{"type":"function","name":"setBudget","inputs":[{"name":"token","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[]}]`))
	if err != nil {
		panic(err)
	}
	return parsed
}()

// Apply delegates to t.Key and sets the account's Permit2 budget to t.Budget.
// Delegating again starts a new epoch, so earlier authorizations stay dead.
func Apply(ctx context.Context, rpcURL, userKey, account string, t Terms) error {
	if t.Cap == nil || t.Budget == nil || t.TTL == 0 || len(t.PayTos) == 0 {
		return fmt.Errorf("delegation: incomplete terms")
	}
	user, err := chain.NewFacilitatorSigner(ctx, rpcURL, userKey, 31337)
	if err != nil {
		return err
	}
	defer user.Close()
	head, err := user.Client().HeaderByNumber(ctx, nil)
	if err != nil {
		return err
	}
	payTos := make([]common.Address, len(t.PayTos))
	for i, p := range t.PayTos {
		payTos[i] = common.HexToAddress(p)
	}
	calls := []struct {
		method string
		args   []any
	}{
		{"delegate", []any{common.HexToAddress(t.Key), t.DID, common.HexToAddress(t.Token), t.Cap, head.Time + t.TTL, payTos}},
		{"setBudget", []any{common.HexToAddress(t.Token), t.Budget}},
	}
	for _, c := range calls {
		data, err := accountABI.Pack(c.method, c.args...)
		if err != nil {
			return err
		}
		tx, err := user.SendTransaction(ctx, account, data)
		if err != nil {
			return fmt.Errorf("delegation: %s: %w", c.method, err)
		}
		receipt, err := user.WaitForTransactionReceipt(ctx, tx)
		if err != nil || receipt.Status != 1 {
			return fmt.Errorf("delegation: %s failed: %v", c.method, err)
		}
	}
	return nil
}
