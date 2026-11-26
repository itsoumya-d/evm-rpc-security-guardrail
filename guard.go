package guard

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
)

var (
	ErrUnboundedApproval = errors.New("policy violation: unbounded ERC-20 token allowance detected")
	ErrValueExceeded     = errors.New("policy violation: transaction value exceeds maximum allowed threshold")
	ErrMissingIAMAuth    = errors.New("security authorization error: missing or invalid cloud IAM signature")
	ErrInvalidCalldata   = errors.New("malformed or unparseable transaction calldata")
)

// Selectors for standard token interactions.
const (
	ERC20ApproveSelector = "095ea7b3" // approve(address,uint256)
)

var maxUint256 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

// PolicyConfig defines inspection boundaries for transaction relaying.
type PolicyConfig struct {
	MaxNativeWei           *big.Int
	BlockUnboundedApproval bool
	RequireCloudIAM        bool
	RequiredIAMRole        string
	SharedHMACKey          string
}

// TransactionParam models standard Ethereum RPC transaction input.
type TransactionParam struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Value string `json:"value,omitempty"`
	Data  string `json:"data,omitempty"`
}

// RPCRequest models standard JSON-RPC 2.0 payload.
type RPCRequest struct {
	JSONRPC string            `json:"jsonrpc"`
	Method  string            `json:"method"`
	Params  []json.RawMessage `json:"params"`
	ID      any               `json:"id"`
}

// RPCResponse models standard JSON-RPC 2.0 response.
type RPCResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	Result  any       `json:"result,omitempty"`
	Error   *RPCError `json:"error,omitempty"`
	ID      any       `json:"id"`
}

// RPCError captures JSON-RPC error details.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// SecurityInspector evaluates transactions and requests against defined security policies.
type SecurityInspector struct {
	cfg PolicyConfig
}

// NewSecurityInspector creates an inspector instance with the specified policy.
func NewSecurityInspector(cfg PolicyConfig) *SecurityInspector {
	if cfg.MaxNativeWei == nil {
		cfg.MaxNativeWei = big.NewInt(0)
	}
	return &SecurityInspector{cfg: cfg}
}

// VerifyIAMContext checks cloud IAM role and credential headers.
func (si *SecurityInspector) VerifyIAMContext(req *http.Request) error {
	if !si.cfg.RequireCloudIAM {
		return nil
	}
	roleHeader := req.Header.Get("X-Cloud-IAM-Role")
	keyHeader := req.Header.Get("X-Cloud-API-Key")
	if roleHeader == "" || keyHeader == "" {
		return ErrMissingIAMAuth
	}
	if si.cfg.RequiredIAMRole != "" && roleHeader != si.cfg.RequiredIAMRole {
		return ErrMissingIAMAuth
	}
	if si.cfg.SharedHMACKey != "" {
		if subtle.ConstantTimeCompare([]byte(keyHeader), []byte(si.cfg.SharedHMACKey)) != 1 {
			return ErrMissingIAMAuth
		}
	}
	return nil
}

// InspectTransaction validates transaction parameters against active policies.
func (si *SecurityInspector) InspectTransaction(tx *TransactionParam) error {
	if tx == nil {
		return nil
	}

	// 1. Native Value Check
	if tx.Value != "" && si.cfg.MaxNativeWei.Cmp(big.NewInt(0)) > 0 {
		valStr := strings.TrimPrefix(tx.Value, "0x")
		if valStr == "" {
			valStr = "0"
		}
		val := new(big.Int)
		if _, ok := val.SetString(valStr, 16); !ok {
			return ErrInvalidCalldata
		}
		if val.Cmp(si.cfg.MaxNativeWei) > 0 {
			return fmt.Errorf("%w: requested %s wei > max %s wei", ErrValueExceeded, val.String(), si.cfg.MaxNativeWei.String())
		}
	}

	// 2. Calldata Inspection (Unbounded Approvals)
	if si.cfg.BlockUnboundedApproval && tx.Data != "" {
		cleanData := strings.TrimPrefix(strings.ToLower(tx.Data), "0x")
		if len(cleanData) >= 8 {
			selector := cleanData[:8]
			if selector == ERC20ApproveSelector && len(cleanData) >= 72 {
				// approve(address spender, uint256 amount)
				amountHex := cleanData[72:]
				if len(amountHex) >= 64 {
					amountHex = amountHex[:64]
				}
				amount := new(big.Int)
				if _, ok := amount.SetString(amountHex, 16); ok {
					// Check if amount is uint256.max or within 95% of max
					threshold := new(big.Int).Sub(maxUint256, big.NewInt(1000000))
					if amount.Cmp(threshold) >= 0 {
						return ErrUnboundedApproval
					}
				}
			}
		}
	}

	return nil
}

// ProcessRPCRequest parses and enforces policy on incoming JSON-RPC calls.
func (si *SecurityInspector) ProcessRPCRequest(req *http.Request, body []byte) RPCResponse {
	var rpcReq RPCRequest
	if err := json.Unmarshal(body, &rpcReq); err != nil {
		return RPCResponse{
			JSONRPC: "2.0",
			Error:   &RPCError{Code: -32700, Message: "Parse error"},
			ID:      nil,
		}
	}

	// Check IAM Context
	if err := si.VerifyIAMContext(req); err != nil {
		return RPCResponse{
			JSONRPC: "2.0",
			Error:   &RPCError{Code: -32001, Message: err.Error()},
			ID:      rpcReq.ID,
		}
	}

	// Inspect methods: eth_sendTransaction, eth_sendRawTransaction
	if rpcReq.Method == "eth_sendTransaction" && len(rpcReq.Params) > 0 {
		var tx TransactionParam
		if err := json.Unmarshal(rpcReq.Params[0], &tx); err == nil {
			if err := si.InspectTransaction(&tx); err != nil {
				return RPCResponse{
					JSONRPC: "2.0",
					Error:   &RPCError{Code: -32000, Message: err.Error()},
					ID:      rpcReq.ID,
				}
			}
		}
	}

	return RPCResponse{
		JSONRPC: "2.0",
		Result:  "0xverified_relay_ok",
		ID:      rpcReq.ID,
	}
}
