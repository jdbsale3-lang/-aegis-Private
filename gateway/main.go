// AEGIS Module 3: MCP Security Gateway
// Transparent proxy for Model Context Protocol traffic
// Written in Go for low-latency, high-concurrency requirements

package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Config holds the MCP gateway configuration
type Config struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Upstream      string `json:"upstream"`
	SandboxMode   bool   `json:"sandbox_mode"`
	MaxTools      int    `json:"max_tools_per_server"`
	RateLimit     int    `json:"rate_limit_per_second"`
	LogAllTraffic bool   `json:"log_all_traffic"`
}

// ToolDescription represents an MCP tool's schema
type ToolDescription struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// ToolAudit holds the result of auditing a tool description
type ToolAudit struct {
	ToolName      string `json:"tool_name"`
	ExpectedBehavior string `json:"expected_behavior"`
	ActualBehavior string `json:"actual_behavior"`
	RiskLevel     string `json:"risk_level"` // low, medium, high, critical
	Issues        []string `json:"issues"`
}

// AuditLogEntry stores a single audited MCP call
type AuditLogEntry struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	ServerID  string    `json:"server_id"`
	ToolName  string    `json:"tool_name"`
	InputHash string    `json:"input_hash"`
	Allowed   bool      `json:"allowed"`
	LatencyMs int64     `json:"latency_ms"`
	RiskLevel string    `json:"risk_level"`
}

// MCPGateway is the main proxy server
type MCPGateway struct {
	config    Config
	proxy     *httputil.ReverseProxy
	auditLog  []AuditLogEntry
	mu        sync.RWMutex
	trustedServers map[string]bool
}

// NewMCPGateway creates a new MCP gateway
func NewMCPGateway(config Config) *MCPGateway {
	upstreamURL, err := url.Parse(config.Upstream)
	if err != nil && config.Upstream != "" {
		log.Fatalf("Invalid upstream URL: %v", err)
	}

	gw := &MCPGateway{
		config: config,
		trustedServers: make(map[string]bool),
		auditLog: make([]AuditLogEntry, 0),
	}

	if upstreamURL != nil {
		gw.proxy = httputil.NewSingleHostReverseProxy(upstreamURL)
	}

	return gw
}

// validateToolDescription audits an MCP tool description for security issues
func (gw *MCPGateway) validateToolDescription(desc ToolDescription) *ToolAudit {
	audit := &ToolAudit{
		ToolName:  desc.Name,
		RiskLevel: "low",
		Issues:    make([]string, 0),
	}

	// 1. Check tool name for suspicious patterns
	suspiciousNames := []string{"exec", "shell", "command", "system", "eval", "execve",
		"popen", "subprocess", "os.system", "rm -rf", "sudo", "chmod", "chown"}
	for _, pattern := range suspiciousNames {
		if strings.Contains(strings.ToLower(desc.Name), pattern) {
			audit.Issues = append(audit.Issues,
				fmt.Sprintf("Tool name contains suspicious pattern: '%s'", pattern))
			audit.RiskLevel = "high"
		}
	}

	// 2. Check input schema for dangerous parameters
	if desc.InputSchema != nil {
		props, ok := desc.InputSchema["properties"].(map[string]interface{})
		if ok {
			for paramName, paramVal := range props {
				paramLower := strings.ToLower(paramName)
				dangerousParams := []string{"command", "shell", "exec", "code", "script",
					"binary", "payload", "eval", "system"}
				for _, danger := range dangerousParams {
					if strings.Contains(paramLower, danger) {
						audit.Issues = append(audit.Issues,
							fmt.Sprintf("Parameter '%s' contains dangerous keyword: '%s'", paramName, danger))
						audit.RiskLevel = "high"
					}
				}

				// Check for shell-injection friendly types
				if paramValObj, ok := paramVal.(map[string]interface{}); ok {
					if paramType, ok := paramValObj["type"].(string); ok {
						if paramType == "string" && strings.Contains(paramLower, "path") {
							// Path traversal detection needed - flag for review
							if audit.RiskLevel == "low" {
								audit.RiskLevel = "medium"
							}
						}
					}
				}
			}
		}
	}

	// 3. Check description for misleading claims
	descLower := strings.ToLower(desc.Description)
	misleadingTerms := []string{"read-only", "safe", "harmless", "no side effects", "benign"}
	for _, term := range misleadingTerms {
		if strings.Contains(descLower, term) {
			// Flag for manual review - tool claiming to be safe but having exec params
			if audit.RiskLevel == "high" {
				audit.Issues = append(audit.Issues,
					fmt.Sprintf("Tool claims '%s' but has dangerous parameters", term))
			}
		}
	}

	return audit
}

// auditToolDescription handles a tool description audit request
func (gw *MCPGateway) auditToolDescription(w http.ResponseWriter, r *http.Request) {
	var desc ToolDescription
	if err := json.NewDecoder(r.Body).Decode(&desc); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid request body: %s"}`, err), http.StatusBadRequest)
		return
	}

	result := gw.validateToolDescription(desc)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// listServers returns all trusted MCP servers
func (gw *MCPGateway) listServers(w http.ResponseWriter, r *http.Request) {
	gw.mu.RLock()
	defer gw.mu.RUnlock()

	servers := make([]string, 0, len(gw.trustedServers))
	for s := range gw.trustedServers {
		servers = append(servers, s)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"servers": servers,
		"count":   len(servers),
	})
}

// trustServer adds an MCP server to the trusted list
func (gw *MCPGateway) trustServer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerID string `json:"server_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	gw.mu.Lock()
	gw.trustedServers[req.ServerID] = true
	gw.mu.Unlock()

	log.Printf("MCP Gateway: Trusted server %s", req.ServerID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "trusted", "server_id": req.ServerID})
}

// removeServer removes a server from the trusted list
func (gw *MCPGateway) removeServer(w http.ResponseWriter, r *http.Request) {
	serverID := strings.TrimPrefix(r.URL.Path, "/api/v1/mcp/servers/")
	if serverID == "" {
		http.Error(w, `{"error":"server_id required"}`, http.StatusBadRequest)
		return
	}

	gw.mu.Lock()
	delete(gw.trustedServers, serverID)
	gw.mu.Unlock()

	log.Printf("MCP Gateway: Removed server %s", serverID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "removed", "server_id": serverID})
}

// middleware is the security middleware for all MCP traffic
func (gw *MCPGateway) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-AEGIS-MCP-Gateway", "1.0")

		// Log the request if enabled
		if gw.config.LogAllTraffic {
			log.Printf("MCP: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
		}

		// Check rate limit (simplified - use token bucket in production)
		// TODO: Implement proper rate limiting

		next.ServeHTTP(w, r)

		// Record latency
		latency := time.Since(start).Milliseconds()
		if gw.config.LogAllTraffic {
			log.Printf("MCP: %s %s completed in %dms", r.Method, r.URL.Path, latency)
		}
	})
}

// healthCheck returns the gateway health status
func (gw *MCPGateway) healthCheck(w http.ResponseWriter, r *http.Request) {
	gw.mu.RLock()
	trustedCount := len(gw.trustedServers)
	gw.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"module":            "mcp_gateway",
		"status":            "healthy",
		"version":           "1.0.0",
		"trusted_servers":   trustedCount,
		"upstream_configured": gw.config.Upstream != "",
		"sandbox_mode":      gw.config.SandboxMode,
	})
}

func main() {
	// Load config from environment
	config := Config{
		Host:          getEnv("AEGIS_MCP_HOST", "0.0.0.0"),
		Port:          8443,
		Upstream:      getEnv("AEGIS_MCP_UPSTREAM", ""),
		SandboxMode:   getEnv("AEGIS_MCP_SANDBOX", "true") == "true",
		MaxTools:      50,
		RateLimit:     100,
		LogAllTraffic: getEnv("AEGIS_MCP_LOG_TRAFFIC", "false") == "true",
	}

	portStr := getEnv("AEGIS_MCP_PORT", "8443")
	fmt.Sscanf(portStr, "%d", &config.Port)

	gw := NewMCPGateway(config)

	// Routes
	mux := http.NewServeMux()

	// Management API
	mux.HandleFunc("/api/v1/mcp/validate", gw.auditToolDescription)
	mux.HandleFunc("/api/v1/mcp/servers", gw.listServers)
	mux.HandleFunc("/api/v1/mcp/servers/trust", gw.trustServer)
	mux.HandleFunc("/api/v1/mcp/servers/", gw.removeServer)
	mux.HandleFunc("/api/v1/mcp/health", gw.healthCheck)

	// Proxy upstream MCP traffic (if configured)
	if gw.proxy != nil && config.Upstream != "" {
		mux.Handle("/mcp/", gw.proxy)
	}

	// Health
	mux.HandleFunc("/health", gw.healthCheck)

	addr := fmt.Sprintf("%s:%d", config.Host, config.Port)
	log.Printf("AEGIS MCP Gateway starting on %s", addr)
	log.Printf("  Sandbox mode: %v", config.SandboxMode)
	log.Printf("  Upstream: %s", config.Upstream)
	log.Printf("  Log traffic: %v", config.LogAllTraffic)

	server := &http.Server{
		Addr:         addr,
		Handler:      gw.middleware(mux),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}