package guard_test

import (
	"bytes"
	"math/big"
	"net/http/httptest"
	"testing"

	guard "github.com/itsoumya-d/evm-rpc-security-guardrail"
)

func TestUnboundedApprovalDetection(t *testing.T) {
	cfg := guard.PolicyConfig{
		BlockUnboundedApproval: true,
	}
	si := guard.NewSecurityInspector(cfg)

	// approve(0x1111111111111111111111111111111111111111, uint256.max)
	unboundedData := "0x095ea7b3" +
		"0000000000000000000000001111111111111111111111111111111111111111" +
		"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	tx := &guard.TransactionParam{
		From: "0x2222222222222222222222222222222222222222",
		To:   "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
		Data: unboundedData,
	}

	err := si.InspectTransaction(tx)
	if err == nil {
		t.Fatalf("expected ErrUnboundedApproval, got nil")
	}

	// Normal approval: 1000 tokens (1000 * 10^18 = 0x3635c9adc5dea00000)
	normalData := "0x095ea7b3" +
		"0000000000000000000000001111111111111111111111111111111111111111" +
		"00000000000000000000000000000000000000000000003635c9adc5dea00000"

	txNormal := &guard.TransactionParam{
		From: "0x2222222222222222222222222222222222222222",
		To:   "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
		Data: normalData,
	}

	if err := si.InspectTransaction(txNormal); err != nil {
		t.Fatalf("expected normal approval to pass, got: %v", err)
	}
}

func TestNativeValueLimit(t *testing.T) {
	// Max allowed: 5 ETH (5 * 10^18 wei = 0x4563918244f40000)
	maxWei, _ := new(big.Int).SetString("5000000000000000000", 10)
	cfg := guard.PolicyConfig{
		MaxNativeWei: maxWei,
	}
	si := guard.NewSecurityInspector(cfg)

	// Transfer 10 ETH (0x8ac7230489e80000) -> should fail
	txOver := &guard.TransactionParam{
		From:  "0xsender",
		To:    "0xrecipient",
		Value: "0x8ac7230489e80000",
	}
	if err := si.InspectTransaction(txOver); err == nil {
		t.Fatalf("expected value limit breach error, got nil")
	}

	// Transfer 1 ETH (0xde0b6b3a7640000) -> should pass
	txUnder := &guard.TransactionParam{
		From:  "0xsender",
		To:    "0xrecipient",
		Value: "0xde0b6b3a7640000",
	}
	if err := si.InspectTransaction(txUnder); err != nil {
		t.Fatalf("expected valid value transfer to pass, got: %v", err)
	}
}

func TestIAMContextVerification(t *testing.T) {
	cfg := guard.PolicyConfig{
		RequireCloudIAM: true,
		RequiredIAMRole: "arn:aws:iam::123456789012:role/ProductionRelayerService",
		SharedHMACKey:   "k_sec_test_secret_token_123",
	}
	si := guard.NewSecurityInspector(cfg)

	// Missing headers
	req := httptest.NewRequest("POST", "/rpc", nil)
	if err := si.VerifyIAMContext(req); err == nil {
		t.Fatalf("expected missing IAM auth error, got nil")
	}

	// Invalid role
	req.Header.Set("X-Cloud-IAM-Role", "arn:aws:iam::123456789012:role/DevRole")
	req.Header.Set("X-Cloud-API-Key", "k_sec_test_secret_token_123")
	if err := si.VerifyIAMContext(req); err == nil {
		t.Fatalf("expected invalid IAM role error, got nil")
	}

	// Valid role and key
	req.Header.Set("X-Cloud-IAM-Role", "arn:aws:iam::123456789012:role/ProductionRelayerService")
	if err := si.VerifyIAMContext(req); err != nil {
		t.Fatalf("expected valid IAM context to pass, got: %v", err)
	}
}

func TestJSONRPCProcessing(t *testing.T) {
	cfg := guard.PolicyConfig{
		BlockUnboundedApproval: true,
	}
	si := guard.NewSecurityInspector(cfg)

	body := []byte(`{
		"jsonrpc": "2.0",
		"method": "eth_sendTransaction",
		"params": [{
			"from": "0x1111",
			"to": "0x2222",
			"data": "0x095ea7b30000000000000000000000001111111111111111111111111111111111111111ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		}],
		"id": 1
	}`)

	req := httptest.NewRequest("POST", "/rpc", bytes.NewReader(body))
	res := si.ProcessRPCRequest(req, body)

	if res.Error == nil || res.Error.Code != -32000 {
		t.Fatalf("expected RPC error code -32000, got: %+v", res.Error)
	}
}
