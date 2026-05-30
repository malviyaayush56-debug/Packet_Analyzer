package com.dpi.service;

import com.dpi.model.AppType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Rule Manager - manages DPI blocking rules.
 * Maps to C++ RuleManager in rule_manager.h
 *
 * Three types of rules:
 *   1. IP Blacklist     - block all traffic from specific source IPs
 *   2. App Blacklist    - block all traffic of a specific app (e.g., YouTube)
 *   3. Domain Blacklist - block any flow whose SNI contains a keyword
 */
@Service
public class RuleManager {

    private static final Logger log = LoggerFactory.getLogger(RuleManager.class);

    private final Set<String> blockedIps      = new HashSet<>();
    private final Set<AppType> blockedApps    = new HashSet<>();
    private final Set<String> blockedDomains  = new HashSet<>();

    // ---- Rule Management ----

    public void addBlockedIp(String ip) {
        blockedIps.add(ip.trim());
        log.info("Added blocked IP: {}", ip);
    }

    public void addBlockedApp(AppType app) {
        blockedApps.add(app);
        log.info("Added blocked app: {}", app);
    }

    public void addBlockedDomain(String domain) {
        blockedDomains.add(domain.toLowerCase().trim());
        log.info("Added blocked domain keyword: {}", domain);
    }

    public void setBlockedIps(List<String> ips) {
        blockedIps.clear();
        if (ips != null) ips.forEach(this::addBlockedIp);
    }

    public void setBlockedApps(List<String> apps) {
        blockedApps.clear();
        if (apps != null) {
            apps.forEach(a -> {
                try {
                    addBlockedApp(AppType.valueOf(a.toUpperCase()));
                } catch (IllegalArgumentException e) {
                    log.warn("Unknown AppType: {}", a);
                }
            });
        }
    }

    public void setBlockedDomains(List<String> domains) {
        blockedDomains.clear();
        if (domains != null) domains.forEach(this::addBlockedDomain);
    }

    public void clearAll() {
        blockedIps.clear();
        blockedApps.clear();
        blockedDomains.clear();
        log.info("All rules cleared");
    }

    // ---- Blocking Check ----

    /**
     * Check if a packet/flow should be blocked.
     *
     * @param srcIp   source IP of the flow
     * @param appType detected application type
     * @param sni     detected SNI hostname (or empty)
     * @return true if should be blocked
     */
    public boolean isBlocked(String srcIp, AppType appType, String sni) {
        // 1. Check IP blacklist
        if (blockedIps.contains(srcIp)) {
            log.debug("Blocked by IP rule: {}", srcIp);
            return true;
        }

        // 2. Check app blacklist
        if (appType != AppType.UNKNOWN && blockedApps.contains(appType)) {
            log.debug("Blocked by app rule: {}", appType);
            return true;
        }

        // 3. Check domain keyword blacklist
        if (sni != null && !sni.isEmpty()) {
            String sniLower = sni.toLowerCase();
            for (String blocked : blockedDomains) {
                if (sniLower.contains(blocked)) {
                    log.debug("Blocked by domain rule: {} matches keyword '{}'", sni, blocked);
                    return true;
                }
            }
        }

        return false;
    }

    // ---- Info ----

    public Set<String> getBlockedIps()       { return Set.copyOf(blockedIps); }
    public Set<AppType> getBlockedApps()     { return Set.copyOf(blockedApps); }
    public Set<String> getBlockedDomains()   { return Set.copyOf(blockedDomains); }

    public String getRulesSummary() {
        return String.format("Rules: %d blocked IPs, %d blocked apps, %d blocked domains",
            blockedIps.size(), blockedApps.size(), blockedDomains.size());
    }
}
