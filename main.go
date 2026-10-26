package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// Vulnerability represents a detected vulnerability
type Vulnerability struct {
	ID          string            `json:"id" yaml:"id"`
	Title       string            `json:"title" yaml:"title"`
	Severity    string            `json:"severity" yaml:"severity"` // critical, high, medium, low, info
	Category    string            `json:"category" yaml:"category"`
	Description string            `json:"description" yaml:"description"`
	Location    string            `json:"location" yaml:"location"`
	CodeSnippet string            `json:"code_snippet,omitempty" yaml:"code_snippet,omitempty"`
	Remediation string            `json:"remediation" yaml:"remediation"`
	References  []string          `json:"references,omitempty" yaml:"references,omitempty"`
	DetectedAt  time.Time         `json:"detected_at" yaml:"detected_at"`
	Metadata    map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// Contract represents a monitored smart contract
type Contract struct {
	ID          string            `json:"id" yaml:"id"`
	Address     string            `json:"address" yaml:"address"`
	Chain       string            `json:"chain" yaml:"chain"`
	Name        string            `json:"name" yaml:"name"`
	ABI         string            `json:"abi,omitempty" yaml:"abi,omitempty"`
	SourceURL   string            `json:"source_url,omitempty" yaml:"source_url,omitempty"`
	DeployedAt  time.Time         `json:"deployed_at,omitempty" yaml:"deployed_at,omitempty"`
	LastScan    time.Time         `json:"last_scan,omitempty" yaml:"last_scan,omitempty"`
	ScanCount   int               `json:"scan_count" yaml:"scan_count"`
	Vulns       []Vulnerability   `json:"vulnerabilities,omitempty" yaml:"vulnerabilities,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	Enabled     bool              `json:"enabled" yaml:"enabled"`
}

// ScanResult represents the result of a scan
type ScanResult struct {
	ContractID   string          `json:"contract_id"`
	ScanID       string          `json:"scan_id"`
	StartedAt    time.Time       `json:"started_at"`
	CompletedAt  time.Time       `json:"completed_at"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	NewVulns     int             `json:"new_vulns"`
	ResolvedVulns int             `json:"resolved_vulns"`
	Error        string          `json:"error,omitempty"`
}

// ChainConfig holds RPC endpoints for each chain
type ChainConfig struct {
	Name      string `json:"name" yaml:"name"`
	RPCURL    string `json:"rpc_url" yaml:"rpc_url"`
	Explorer  string `json:"explorer" yaml:"explorer"`
	ChainID   int64  `json:"chain_id" yaml:"chain_id"`
}

// Config holds the application configuration
type Config struct {
	Chains      map[string]ChainConfig `json:"chains" yaml:"chains"`
	Contracts   []Contract             `json:"contracts" yaml:"contracts"`
	RulesPath   string                 `json:"rules_path" yaml:"rules_path"`
	OutputDir   string                 `json:"output_dir" yaml:"output_dir"`
	ScanInterval string                `json:"scan_interval" yaml:"scan_interval"`
	AlertWebhook string                `json:"alert_webhook,omitempty" yaml:"alert_webhook,omitempty"`
}

// VulnerabilityRule defines a detection rule
type VulnerabilityRule struct {
	ID          string   `json:"id" yaml:"id"`
	Name        string   `json:"name" yaml:"name"`
	Severity    string   `json:"severity" yaml:"severity"`
	Category    string   `json:"category" yaml:"category"`
	Pattern     string   `json:"pattern" yaml:"pattern"`     // Regex pattern for source code
	BytecodeSig string   `json:"bytecode_sig,omitempty" yaml:"bytecode_sig,omitempty"` // 4-byte selector
	Description string   `json:"description" yaml:"description"`
	Remediation string   `json:"remediation" yaml:"remediation"`
	References  []string `json:"references,omitempty" yaml:"references,omitempty"`
}

// Auditor performs continuous smart contract auditing
type Auditor struct {
	config     *Config
	contracts  map[string]*Contract
	rules      []VulnerabilityRule
	clients    map[string]*ethclient.Client
	mu         sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	scanTicker *time.Ticker
	wg         sync.WaitGroup
}

func NewAuditor(configPath string) (*Auditor, error) {
	ctx, cancel := context.WithCancel(context.Background())
	a := &Auditor{
		config:    &Config{},
		contracts: make(map[string]*Contract),
		clients:   make(map[string]*ethclient.Client),
		ctx:       ctx,
		cancel:    cancel,
	}

	if err := a.LoadConfig(configPath); err != nil {
		return nil, err
	}
	if err := a.LoadRules(); err != nil {
		return nil, err
	}
	if err := a.InitClients(); err != nil {
		return nil, err
	}

	return a, nil
}

func (a *Auditor) LoadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Create default config
			return a.CreateDefaultConfig(path)
		}
		return err
	}

	if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
		return yaml.Unmarshal(data, a.config)
	}
	return json.Unmarshal(data, a.config)
}

func (a *Auditor) CreateDefaultConfig(path string) error {
	a.config = &Config{
		Chains: map[string]ChainConfig{
			"ethereum": {
				Name:     "Ethereum Mainnet",
				RPCURL:   "https://eth.llamarpc.com",
				Explorer: "https://etherscan.io",
				ChainID:  1,
			},
			"polygon": {
				Name:     "Polygon",
				RPCURL:   "https://polygon-rpc.com",
				Explorer: "https://polygonscan.com",
				ChainID:  137,
			},
			"arbitrum": {
				Name:     "Arbitrum One",
				RPCURL:   "https://arb1.arbitrum.io/rpc",
				Explorer: "https://arbiscan.io",
				ChainID:  42161,
			},
			"optimism": {
				Name:     "Optimism",
				RPCURL:   "https://mainnet.optimism.io",
				Explorer: "https://optimistic.etherscan.io",
				ChainID:  10,
			},
			"base": {
				Name:     "Base",
				RPCURL:   "https://mainnet.base.org",
				Explorer: "https://basescan.org",
				ChainID:  8453,
			},
			"gnosis": {
				Name:     "Gnosis Chain",
				RPCURL:   "https://rpc.gnosischain.com",
				Explorer: "https://gnosisscan.io",
				ChainID:  100,
			},
		},
		RulesPath:    "./rules",
		OutputDir:    "./reports",
		ScanInterval: "24h",
	}

	os.MkdirAll(filepath.Dir(path), 0755)
	data, _ := yaml.Marshal(a.config)
	return os.WriteFile(path, data, 0644)
}

func (a *Auditor) LoadRules() error {
	rulesDir := a.config.RulesPath
	if rulesDir == "" {
		rulesDir = "./rules"
	}

	// Built-in rules
	a.rules = []VulnerabilityRule{
		{
			ID:          "reentrancy",
			Name:        "Reentrancy Vulnerability",
			Severity:    "critical",
			Category:    "reentrancy",
			Pattern:     `(?i)\.call\{value:.*\}`,
			Description: "External call with value transfer before state update",
			Remediation: "Use checks-effects-interactions pattern; consider ReentrancyGuard",
			References:  []string{"https://swcregistry.io/docs/SWC-107"},
		},
		{
			ID:          "unchecked-return",
			Name:        "Unchecked Return Value",
			Severity:    "medium",
			Category:    "error-handling",
			Pattern:     `\.call\(\)\s*;`,
			Description: "Low-level call return value not checked",
			Remediation: "Always check return values of low-level calls",
			References:  []string{"https://swcregistry.io/docs/SWC-104"},
		},
		{
			ID:          "tx-origin",
			Name:        "tx.origin Authentication",
			Severity:    "high",
			Category:    "authentication",
			Pattern:     `tx\.origin`,
			Description: "Using tx.origin for authorization is vulnerable to phishing",
			Remediation: "Use msg.sender instead of tx.origin",
			References:  []string{"https://swcregistry.io/docs/SWC-115"},
		},
		{
			ID:          "delegatecall",
			Name:        "Dangerous Delegatecall",
			Severity:    "critical",
			Category:    "proxy",
			Pattern:     `delegatecall\s*\(`,
			Description: "Delegatecall to untrusted contracts can lead to storage corruption",
			Remediation: "Restrict delegatecall targets; use EIP-1967 proxy patterns",
			References:  []string{"https://swcregistry.io/docs/SWC-112"},
		},
		{
			ID:          "selfdestruct",
			Name:        "Selfdestruct Usage",
			Severity:    "high",
			Category:    "destruct",
			Pattern:     `selfdestruct\s*\(`,
			Description: "Selfdestruct can be used to force-send Ether and break invariants",
			Remediation: "Avoid selfdestruct; use upgradeable proxy patterns instead",
			References:  []string{"https://swcregistry.io/docs/SWC-106"},
		},
		{
			ID:          "unprotected-function",
			Name:        "Unprotected Critical Function",
			Severity:    "high",
			Category:    "access-control",
			Pattern:     `function\s+(mint|burn|pause|unpause|upgrade|setOwner|transferOwnership)\s*\([^)]*\)\s*(external|public)\s*\{`,
			Description: "Critical admin function lacks access control modifier",
			Remediation: "Add onlyOwner/onlyRole modifiers to all critical functions",
			References:  []string{"https://swcregistry.io/docs/SWC-105"},
		},
		{
			ID:          "timestamp-dependence",
			Name:        "Timestamp Dependence",
			Severity:    "medium",
			Category:    "time",
			Pattern:     `block\.timestamp|now\s*(==|!=|<|>)`,
			Description: "Block timestamp can be manipulated by miners within bounds",
			Remediation: "Avoid using block.timestamp for critical logic; use block.number for time bounds",
			References:  []string{"https://swcregistry.io/docs/SWC-116"},
		},
		{
			ID:          "integer-overflow",
			Name:        "Integer Overflow/Underflow",
			Severity:    "high",
			Category:    "arithmetic",
			Pattern:     `[\+\-\*\/]=\s*[^;]+;`,
			Description: "Arithmetic operations without SafeMath (pre-0.8.0) or unchecked blocks",
			Remediation: "Use Solidity 0.8+ built-in overflow checks or SafeMath library",
			References:  []string{"https://swcregistry.io/docs/SWC-101"},
		},
	}

	// Load custom rules from directory
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return a.SaveDefaultRules(rulesDir)
		}
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}
		data, _ := os.ReadFile(filepath.Join(rulesDir, entry.Name()))
		var rule VulnerabilityRule
		if yaml.Unmarshal(data, &rule) == nil && rule.ID != "" {
			a.rules = append(a.rules, rule)
		}
	}
	return nil
}

func (a *Auditor) SaveDefaultRules(dir string) error {
	os.MkdirAll(dir, 0755)
	for _, rule := range a.rules {
		data, _ := yaml.Marshal(rule)
		os.WriteFile(filepath.Join(dir, rule.ID+".yaml"), data, 0644)
	}
	return nil
}

func (a *Auditor) InitClients() error {
	for name, chain := range a.config.Chains {
		client, err := ethclient.Dial(chain.RPCURL)
		if err != nil {
			log.Printf("Warning: Failed to connect to %s: %v", name, err)
			continue
		}
		a.clients[name] = client
	}
	return nil
}

func (a *Auditor) AddContract(address, chain, name, abiStr, sourceURL string) (*Contract, error) {
	if !common.IsHexAddress(address) {
		return nil, fmt.Errorf("invalid address: %s", address)
	}
	if _, ok := a.config.Chains[chain]; !ok {
		return nil, fmt.Errorf("unsupported chain: %s", chain)
	}

	id := uuid.New().String()
	contract := &Contract{
		ID:        id,
		Address:   strings.ToLower(address),
		Chain:     chain,
		Name:      name,
		ABI:       abiStr,
		SourceURL: sourceURL,
		Enabled:   true,
		Metadata:  make(map[string]string),
	}

	a.mu.Lock()
	a.contracts[id] = contract
	a.config.Contracts = append(a.config.Contracts, *contract)
	a.mu.Unlock()

	return contract, a.SaveConfig()
}

func (a *Auditor) RemoveContract(id string) error {
	a.mu.Lock()
	delete(a.contracts, id)
	// Remove from config
	newContracts := make([]Contract, 0)
	for _, c := range a.config.Contracts {
		if c.ID != id {
			newContracts = append(newContracts, c)
		}
	}
	a.config.Contracts = newContracts
	a.mu.Unlock()
	return a.SaveConfig()
}

func (a *Auditor) SaveConfig() error {
	a.mu.RLock()
	data, _ := yaml.Marshal(a.config)
	a.mu.RUnlock()
	return os.WriteFile(a.configPath(), data, 0644)
}

func (a *Auditor) configPath() string {
	// This would be passed in real implementation
	return "./config.yaml"
}

func (a *Auditor) ScanContract(contract *Contract) (*ScanResult, error) {
	client, ok := a.clients[contract.Chain]
	if !ok {
		return nil, fmt.Errorf("no client for chain %s", contract.Chain)
	}

	scanID := uuid.New().String()
	result := &ScanResult{
		ContractID:   contract.ID,
		ScanID:       scanID,
		StartedAt:    time.Now(),
		Vulnerabilities: []Vulnerability{},
	}

	// Get contract code
	addr := common.HexToAddress(contract.Address)
	code, err := client.CodeAt(context.Background(), addr, nil)
	if err != nil {
		result.Error = err.Error()
		result.CompletedAt = time.Now()
		return result, err
	}

	if len(code) == 0 {
		result.Error = "no code at address (not a contract)"
		result.CompletedAt = time.Now()
		return result, fmt.Errorf("no code at address")
	}

	// If we have source code, scan it
	if contract.SourceURL != "" {
		vulns := a.scanSourceCode(contract)
		result.Vulnerabilities = vulns
	}

	// Bytecode analysis
	vulns := a.scanBytecode(code, contract)
	result.Vulnerabilities = append(result.Vulnerabilities, vulns...)

	result.CompletedAt = time.Now()

	// Calculate new vs resolved
	a.mu.Lock()
	oldVulns := make(map[string]Vulnerability)
	for _, v := range contract.Vulns {
		oldVulns[v.ID] = v
	}
	contract.Vulns = result.Vulnerabilities
	contract.LastScan = time.Now()
	contract.ScanCount++
	a.mu.Unlock()

	for _, v := range result.Vulnerabilities {
		if _, ok := oldVulns[v.ID]; !ok {
			result.NewVulns++
		}
	}
	for _, v := range oldVulns {
		found := false
		for _, nv := range result.Vulnerabilities {
			if nv.ID == v.ID {
				found = true
				break
			}
		}
		if !found {
			result.ResolvedVulns++
		}
	}

	// Save report
	a.saveReport(contract, result)

	// Send alert if new critical/high vulns
	if result.NewVulns > 0 && a.config.AlertWebhook != "" {
		a.sendAlert(contract, result)
	}

	return result, nil
}

func (a *Auditor) scanSourceCode(contract *Contract) []Vulnerability {
	var vulns []Vulnerability
	// In production, fetch source from Etherscan/Sourcify
	// For now, return empty - would need HTTP client to fetch
	return vulns
}

func (a *Auditor) scanBytecode(code []byte, contract *Contract) []Vulnerability {
	var vulns []Vulnerability
	codeStr := string(code)

	for _, rule := range a.rules {
		if rule.BytecodeSig != "" {
			// Check for 4-byte function selector
			if strings.Contains(codeStr, rule.BytecodeSig) {
				vulns = append(vulns, Vulnerability{
					ID:          rule.ID + "-" + contract.ID[:8],
					Title:       rule.Name,
					Severity:    rule.Severity,
					Category:    rule.Category,
					Description: rule.Description,
					Location:    fmt.Sprintf("%s:%s", contract.Chain, contract.Address),
					Remediation: rule.Remediation,
					References:  rule.References,
					DetectedAt:  time.Now(),
					Metadata: map[string]string{
						"rule_id":     rule.ID,
						"contract_id": contract.ID,
					},
				})
			}
		}
	}
	return vulns
}

func (a *Auditor) saveReport(contract *Contract, result *ScanResult) {
	os.MkdirAll(a.config.OutputDir, 0755)
	filename := fmt.Sprintf("%s_%s_%s.json",
		contract.Chain,
		contract.Address[:10],
		result.ScanID[:8])
	path := filepath.Join(a.config.OutputDir, filename)

	data, _ := json.MarshalIndent(map[string]interface{}{
		"contract":  contract,
		"scan":      result,
		"timestamp": time.Now(),
	}, "", "  ")
	os.WriteFile(path, data, 0644)
}

func (a *Auditor) sendAlert(contract *Contract, result *ScanResult) {
	// In production, POST to webhook
	log.Printf("ALERT: Contract %s (%s) has %d new vulnerabilities",
		contract.Name, contract.Address, result.NewVulns)
}

func (a *Auditor) ScanAll() []*ScanResult {
	a.mu.RLock()
	contracts := make([]*Contract, 0, len(a.contracts))
	for _, c := range a.contracts {
		if c.Enabled {
			contracts = append(contracts, c)
		}
	}
	a.mu.RUnlock()

	results := make([]*ScanResult, 0, len(contracts))
	for _, c := range contracts {
		result, err := a.ScanContract(c)
		if err != nil {
			log.Printf("Scan failed for %s: %v", c.Name, err)
		}
		results = append(results, result)
	}
	return results
}

func (a *Auditor) StartScheduler() {
	interval, _ := time.ParseDuration(a.config.ScanInterval)
	if interval == 0 {
		interval = 24 * time.Hour
	}

	a.scanTicker = time.NewTicker(interval)
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		// Initial scan
		a.ScanAll()

		for {
			select {
			case <-a.ctx.Done():
				return
			case <-a.scanTicker.C:
				a.ScanAll()
			}
		}
	}()
}

func (a *Auditor) Stop() {
	if a.scanTicker != nil {
		a.scanTicker.Stop()
	}
	a.cancel()
	a.wg.Wait()
}

func (a *Auditor) GetContract(id string) (*Contract, bool) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	c, ok := a.contracts[id]
	return c, ok
}

func (a *Auditor) ListContracts() []*Contract {
	a.mu.RLock()
	defer a.mu.RUnlock()
	list := make([]*Contract, 0, len(a.contracts))
	for _, c := range a.contracts {
		list = append(list, c)
	}
	return list
}

func main() {
	var (
		configPath = flag.String("config", "./config.yaml", "Path to config file")
		action     = flag.String("action", "", "Action: add, remove, list, scan, scan-all, report, serve")
		address    = flag.String("address", "", "Contract address (for add)")
		chain      = flag.String("chain", "ethereum", "Chain name (for add)")
		name       = flag.String("name", "", "Contract name (for add)")
		abiFile    = flag.String("abi", "", "ABI file path (for add)")
		sourceURL  = flag.String("source", "", "Source code URL (for add)")
		id         = flag.String("id", "", "Contract ID (for remove/scan/report)")
		outputDir  = flag.String("output", "./reports", "Output directory for reports")
		port       = flag.Int("port", 8080, "HTTP server port (for serve)")
	)
	flag.Parse()

	auditor, err := NewAuditor(*configPath)
	if err != nil {
		log.Fatalf("Failed to initialize auditor: %v", err)
	}
	defer auditor.Stop()

	// Override output dir if provided
	if *outputDir != "./reports" {
		auditor.config.OutputDir = *outputDir
	}

	switch *action {
	case "add":
		if *address == "" || *name == "" {
			log.Fatal("address and name required for add")
		}
		abiStr := ""
		if *abiFile != "" {
			data, _ := os.ReadFile(*abiFile)
			abiStr = string(data)
		}
		contract, err := auditor.AddContract(*address, *chain, *name, abiStr, *sourceURL)
		if err != nil {
			log.Fatalf("Failed to add contract: %v", err)
		}
		fmt.Printf("Added contract %s (ID: %s)\n", contract.Name, contract.ID)

	case "remove":
		if *id == "" {
			log.Fatal("id required for remove")
		}
		if err := auditor.RemoveContract(*id); err != nil {
			log.Fatalf("Failed to remove contract: %v", err)
		}
		fmt.Printf("Removed contract %s\n", *id)

	case "list":
		contracts := auditor.ListContracts()
		if len(contracts) == 0 {
			fmt.Println("No contracts configured")
			return
		}
		for _, c := range contracts {
			status := "enabled"
			if !c.Enabled {
				status = "disabled"
			}
			fmt.Printf("%s | %s | %s | %s | scans=%d | %s\n",
				c.ID[:8], c.Name, c.Chain, c.Address[:10]+"...", c.ScanCount, status)
		}

	case "scan":
		if *id == "" {
			log.Fatal("id required for scan")
		}
		contract, ok := auditor.GetContract(*id)
		if !ok {
			log.Fatalf("Contract %s not found", *id)
		}
		result, err := auditor.ScanContract(contract)
		if err != nil {
			log.Fatalf("Scan failed: %v", err)
		}
		data, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(data))

	case "scan-all":
		results := auditor.ScanAll()
		fmt.Printf("Scanned %d contracts\n", len(results))
		for _, r := range results {
			fmt.Printf("  %s: %d vulns (%d new, %d resolved)\n",
				r.ContractID[:8], len(r.Vulnerabilities), r.NewVulns, r.ResolvedVulns)
		}

	case "report":
		if *id == "" {
			log.Fatal("id required for report")
		}
		contract, ok := auditor.GetContract(*id)
		if !ok {
			log.Fatalf("Contract %s not found", *id)
		}
		data, _ := json.MarshalIndent(contract, "", "  ")
		fmt.Println(string(data))

	case "serve":
		// Start HTTP API server
		auditor.StartScheduler()
		log.Printf("Starting auditor on port %d...", *port)
		// HTTP server would go here
		select {}

	default:
		flag.Usage()
		os.Exit(1)
	}
}