package com.dpi.controller;

import com.dpi.model.AppType;
import com.dpi.model.DpiReport;
import com.dpi.service.DpiEngine;
import com.dpi.service.RuleManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;

/**
 * REST API Controller for the DPI Engine.
 *
 * Endpoints:
 * POST /api/dpi/analyze         - Upload PCAP file and get analysis report
 * GET  /api/dpi/rules           - View current blocking rules
 * POST /api/dpi/rules/ip        - Add blocked IP
 * POST /api/dpi/rules/app       - Add blocked app (e.g., YOUTUBE)
 * POST /api/dpi/rules/domain    - Add blocked domain keyword
 * DELETE /api/dpi/rules         - Clear all rules
 * DELETE /api/dpi/rules/domain/{name} - Unblock/Remove a specific domain
 * GET  /api/dpi/health          - Health check
 */
@RestController
@RequestMapping("/api/dpi")
@CrossOrigin(origins = "*")
public class DpiController {

    private static final Logger log = LoggerFactory.getLogger(DpiController.class);

    private final DpiEngine dpiEngine;
    private final RuleManager ruleManager;

    @Autowired
    public DpiController(DpiEngine dpiEngine, RuleManager ruleManager) {
        this.dpiEngine   = dpiEngine;
        this.ruleManager = ruleManager;
    }

    // =====================================================================
    // MAIN ANALYSIS ENDPOINT
    // =====================================================================

    /**
     * Upload a PCAP file and run DPI analysis on it.
     */
    @PostMapping("/analyze")
    public ResponseEntity<?> analyze(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "blockApps",    required = false) List<String> blockApps,
            @RequestParam(value = "blockIps",     required = false) List<String> blockIps,
            @RequestParam(value = "blockDomains", required = false) List<String> blockDomains) {

        try {
            if (file.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "PCAP file is empty"));
            }

            log.info("Received PCAP file: {} ({} bytes)", file.getOriginalFilename(), file.getSize());

            // Apply rules from request parameters
            ruleManager.clearAll();
            if (blockApps    != null) ruleManager.setBlockedApps(blockApps);
            if (blockIps     != null) ruleManager.setBlockedIps(blockIps);
            if (blockDomains != null) ruleManager.setBlockedDomains(blockDomains);

            // Run analysis
            DpiReport report = dpiEngine.analyze(file.getBytes());

            return ResponseEntity.ok(report);

        } catch (Exception e) {
            log.error("Analysis failed: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", "Analysis failed: " + e.getMessage()));
        }
    }

    // =====================================================================
    // RULE MANAGEMENT ENDPOINTS
    // =====================================================================

    /** Get current blocking rules */
    @GetMapping("/rules")
    public ResponseEntity<?> getRules() {
        return ResponseEntity.ok(Map.of(
                "blockedIps",     ruleManager.getBlockedIps(),
                "blockedApps",    ruleManager.getBlockedApps(),
                "blockedDomains", ruleManager.getBlockedDomains(),
                "summary",        ruleManager.getRulesSummary()
        ));
    }

    /** Add a blocked IP address */
    @PostMapping("/rules/ip")
    public ResponseEntity<?> addBlockedIp(@RequestBody Map<String, String> body) {
        String ip = body.get("ip");
        if (ip == null || ip.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "IP address required"));
        }
        ruleManager.addBlockedIp(ip);
        return ResponseEntity.ok(Map.of("message", "Blocked IP added: " + ip));
    }

    /** Add a blocked application */
    @PostMapping("/rules/app")
    public ResponseEntity<?> addBlockedApp(@RequestBody Map<String, String> body) {
        String app = body.get("app");
        try {
            AppType appType = AppType.valueOf(app.toUpperCase());
            ruleManager.addBlockedApp(appType);
            return ResponseEntity.ok(Map.of("message", "Blocked app added: " + appType));
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Unknown app type: " + app,
                    "validApps", List.of(AppType.values()).stream().map(Enum::name).toList()
            ));
        }
    }

    /** Add a blocked domain keyword */
    @PostMapping("/rules/domain")
    public ResponseEntity<?> addBlockedDomain(@RequestBody Map<String, String> body) {
        String domain = body.get("domain");
        if (domain == null || domain.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Domain keyword required"));
        }
        ruleManager.addBlockedDomain(domain);
        return ResponseEntity.ok(Map.of("message", "Blocked domain added: " + domain));
    }

    /** Clear all rules */
    @DeleteMapping("/rules")
    public ResponseEntity<?> clearRules() {
        ruleManager.clearAll();
        return ResponseEntity.ok(Map.of("message", "All rules cleared"));
    }

    /** Unblock / Delete a specific domain keyword */
    @DeleteMapping("/rules/domain/{name}")
    public ResponseEntity<?> removeDomain(@PathVariable("name") String name) {
        if (name == null || name.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Domain name keyword required"));
        }

        log.info("Request received to unblock domain: {}", name);

        // Yeh line active kar di hai jo RuleManager se domain delete karegi
        ruleManager.removeBlockedDomain(name);

        return ResponseEntity.ok(Map.of(
                "message", "Unlocked domain: " + name,
                "blockedDomains", ruleManager.getBlockedDomains()
        ));
    }

    // =====================================================================
    // INFO ENDPOINTS
    // =====================================================================

    /** Health check */
    @GetMapping("/health")
    public ResponseEntity<?> health() {
        return ResponseEntity.ok(Map.of(
                "status",  "UP",
                "service", "DPI Engine - Packet Analyzer",
                "version", "1.0.0 (Java Spring Boot port of C++ engine)"
        ));
    }

    /** List all supported app types */
    @GetMapping("/apps")
    public ResponseEntity<?> getSupportedApps() {
        return ResponseEntity.ok(Map.of(
                "apps", List.of(AppType.values()).stream().map(Enum::name).toList()
        ));
    }

}
