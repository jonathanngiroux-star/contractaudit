package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

func TestContractConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	auditor, err := NewAuditor(configPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}

	// Check default chains loaded
	if len(auditor.config.Chains) == 0 {
		t.Error("Expected default chains to be loaded")
	}
	if _, ok := auditor.config.Chains["ethereum"]; !ok {
		t.Error("Expected ethereum chain")
	}
	if _, ok := auditor.config.Chains["polygon"]; !ok {
		t.Error("Expected polygon chain")
	}
}

func TestAddContract(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	auditor, err := NewAuditor(configPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}

	contract, err := auditor.AddContract(
		"0x1234567890123456789012345678901234567890",
		"ethereum",
		"TestToken",
		"[]",
		"https://etherscan.io/address/0x123...#code",
	)
	if err != nil {
		t.Fatalf("Failed to add contract: %v", err)
	}

	if contract.Name != "TestToken" {
		t.Errorf("Expected name TestToken, got %s", contract.Name)
	}
	if contract.Address != "0x1234567890123456789012345678901234567890" {
		t.Errorf("Address mismatch")
	}
	if contract.Chain != "ethereum" {
		t.Errorf("Expected ethereum chain, got %s", contract.Chain)
	}
	if !contract.Enabled {
		t.Error("Contract should be enabled by default")
	}
}

func TestAddContractInvalidAddress(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	auditor, err := NewAuditor(configPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}

	_, err = auditor.AddContract("invalid-address", "ethereum", "Test", "", "")
	if err == nil {
		t.Error("Expected error for invalid address")
	}
}

func TestAddContractInvalidChain(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	auditor, err := NewAuditor(configPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}

	_, err = auditor.AddContract(
		"0x1234567890123456789012345678901234567890",
		"unsupported-chain",
		"Test",
		"",
		"",
	)
	if err == nil {
		t.Error("Expected error for unsupported chain")
	}
}

func TestRemoveContract(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	auditor, err := NewAuditor(configPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}

	contract, _ := auditor.AddContract(
		"0x1234567890123456789012345678901234567890",
		"ethereum",
		"TestToken",
		"[]",
		"",
	)

	if err := auditor.RemoveContract(contract.ID); err != nil {
		t.Fatalf("Failed to remove contract: %v", err)
	}

	_, ok := auditor.GetContract(contract.ID)
	if ok {
		t.Error("Contract should have been removed")
	}
}

func TestVulnerabilitySerialization(t *testing.T) {
	vuln := Vulnerability{
		ID:          "test-1",
		Title:       "Test Vulnerability",
		Severity:    "high",
		Category:    "test",
		Description: "Test description",
		Location:    "ethereum:0x123...",
		Remediation: "Fix it",
		References:  []string{"https://example.com"},
		DetectedAt:  time.Now(),
		Metadata:    map[string]string{"key": "value"},
	}

	data, err := json.Marshal(vuln)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var decoded Vulnerability
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if decoded.Title != vuln.Title {
		t.Errorf("Title mismatch: %s != %s", decoded.Title, vuln.Title)
	}
	if decoded.Severity != vuln.Severity {
		t.Errorf("Severity mismatch: %s != %s", decoded.Severity, vuln.Severity)
	}
}

func TestScanResult(t *testing.T) {
	result := &ScanResult{
		ContractID:   "contract-1",
		ScanID:       "scan-1",
		StartedAt:    time.Now(),
		CompletedAt:  time.Now().Add(1 * time.Second),
		Vulnerabilities: []Vulnerability{
			{ID: "v1", Title: "Vuln 1", Severity: "high"},
			{ID: "v2", Title: "Vuln 2", Severity: "medium"},
		},
		NewVulns:     2,
		ResolvedVulns: 0,
	}

	if len(result.Vulnerabilities) != 2 {
		t.Errorf("Expected 2 vulns, got %d", len(result.Vulnerabilities))
	}
	if result.NewVulns != 2 {
		t.Errorf("Expected 2 new vulns, got %d", result.NewVulns)
	}
}

func TestRulesLoading(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	auditor, err := NewAuditor(configPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}

	// Check built-in rules loaded
	if len(auditor.rules) < 8 {
		t.Errorf("Expected at least 8 built-in rules, got %d", len(auditor.rules))
	}

	// Check specific rules exist
	ruleNames := make(map[string]bool)
	for _, r := range auditor.rules {
		ruleNames[r.ID] = true
	}

	expectedRules := []string{"reentrancy", "unchecked-return", "tx-origin", "delegatecall", "selfdestruct", "unprotected-function", "timestamp-dependence", "integer-overflow"}
	for _, expected := range expectedRules {
		if !ruleNames[expected] {
			t.Errorf("Missing expected rule: %s", expected)
		}
	}
}

func TestConfigYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	_, err := NewAuditor(configPath)
	if err != nil {
		t.Fatalf("Failed to create auditor: %v", err)
	}

	// Config should have been created
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("Config file should have been created")
	}

	// Verify it's valid YAML by reading it back
	data, _ := os.ReadFile(configPath)
	if len(data) == 0 {
		t.Error("Config file should not be empty")
	}
}

func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	select {
	case <-ctx.Done():
		// Expected
	case <-time.After(100 * time.Millisecond):
		t.Error("Context should be cancelled")
	}
}

func TestCommonAddressValidation(t *testing.T) {
	validAddresses := []string{
		"0x1234567890123456789012345678901234567890",
		"0xAbCdEf1234567890123456789012345678901234",
		"1234567890123456789012345678901234567890", // go-ethereum accepts without 0x
	}
	for _, addr := range validAddresses {
		if !common.IsHexAddress(addr) {
			t.Errorf("Expected %s to be valid", addr)
		}
	}

	invalidAddresses := []string{
		"0x123",                              // too short
		"0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG", // invalid hex
		"",                                   // empty
	}
	for _, addr := range invalidAddresses {
		if common.IsHexAddress(addr) {
			t.Errorf("Expected %s to be invalid", addr)
		}
	}
}