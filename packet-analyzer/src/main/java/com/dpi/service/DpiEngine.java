package com.dpi.service;

import com.dpi.model.*;
import com.dpi.service.PcapReader.RawPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;
// Yeh add karo file ke top par
import com.dpi.model.Flow;  // ✅ Tumhari custom Flow class

/**
 * DPI Engine - Main Orchestrator.
 * Maps to C++ DpiEngine and main_working.cpp / dpi_mt.cpp
 *
 * Flow:
 *   PCAP bytes → PcapReader → PacketParser → SniExtractor
 *              → AppClassifier → RuleManager → Report
 *
 * Multi-threaded design:
 *   Uses a thread pool to process packets in parallel.
 *   Each flow is tracked in a ConcurrentHashMap keyed by FiveTuple.
 */
@Service
public class DpiEngine {

    private static final Logger log = LoggerFactory.getLogger(DpiEngine.class);

    private final PcapReader pcapReader;
    private final PacketParser packetParser;
    private final SniExtractor sniExtractor;
    private final AppClassifier appClassifier;
    private final RuleManager ruleManager;

    @Autowired
    public DpiEngine(PcapReader pcapReader,
                     PacketParser packetParser,
                     SniExtractor sniExtractor,
                     AppClassifier appClassifier,
                     RuleManager ruleManager) {
        this.pcapReader    = pcapReader;
        this.packetParser  = packetParser;
        this.sniExtractor  = sniExtractor;
        this.appClassifier = appClassifier;
        this.ruleManager   = ruleManager;
    }

    /**
     * Analyze a PCAP file and return a report.
     *
     * @param pcapBytes raw bytes of the PCAP file
     * @return DpiReport with full analysis
     */
    public DpiReport analyze(byte[] pcapBytes) throws IOException {
        log.info("DPI Engine starting. {}", ruleManager.getRulesSummary());

        // 1. Read all raw packets
        List<RawPacket> rawPackets = pcapReader.readAll(pcapBytes);
        log.info("Loaded {} raw packets", rawPackets.size());

        // 2. Flow table: FiveTuple → Flow
        //    ConcurrentHashMap for thread-safe multi-threaded access
        ConcurrentHashMap<FiveTuple, Flow> flowTable = new ConcurrentHashMap<>();

        // 3. Counters
        long[] totalBytes  = {0};
        int[]  tcpCount    = {0};
        int[]  udpCount    = {0};
        int[]  forwarded   = {0};
        int[]  dropped     = {0};

        // 4. Multi-threaded processing with a thread pool
        int threads = Math.min(Runtime.getRuntime().availableProcessors(), 8);
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Future<?>> futures = new ArrayList<>();

        for (RawPacket raw : rawPackets) {
            futures.add(pool.submit(() -> {
                try {
                    processPacket(raw, flowTable, totalBytes, tcpCount, udpCount, forwarded, dropped);
                } catch (Exception e) {
                    log.warn("Error processing packet: {}", e.getMessage());
                }
            }));
        }

        // Wait for all packets to be processed
        for (Future<?> f : futures) {
            try { f.get(); } catch (Exception e) { log.warn("Thread error: {}", e.getMessage()); }
        }
        pool.shutdown();

        log.info("Processing complete. Forwarded={}, Dropped={}", forwarded[0], dropped[0]);

        // 5. Build report
        return buildReport(rawPackets.size(), totalBytes[0], tcpCount[0], udpCount[0],
                           forwarded[0], dropped[0], flowTable);
    }

    /**
     * Process a single raw packet through the full DPI pipeline.
     * This is called from the thread pool.
     */
    private void processPacket(
            RawPacket raw,
            ConcurrentHashMap<FiveTuple, Flow> flowTable,
            long[] totalBytes, int[] tcpCount, int[] udpCount,
            int[] forwarded, int[] dropped) {

        // --- Parse headers ---
        ParsedPacket pkt = packetParser.parse(raw);
        if (!pkt.isValid()) return;

        synchronized (totalBytes) { totalBytes[0] += raw.data.length; }
        if (pkt.isHasTcp()) synchronized (tcpCount)  { tcpCount[0]++; }
        if (pkt.isHasUdp()) synchronized (udpCount)  { udpCount[0]++; }

        FiveTuple tuple = pkt.toFiveTuple();

        // --- Get or create flow ---
        Flow flow = flowTable.computeIfAbsent(tuple, Flow::new);
        flow.addPacket(raw.data.length);

        // --- Deep Packet Inspection ---
        // Only attempt SNI/Host extraction if the flow isn't classified yet
        if (flow.getAppType() == AppType.UNKNOWN && pkt.getPayloadLength() > 5) {

            // TLS SNI extraction (HTTPS port 443)
            if (pkt.getDstPort() == PacketParser.PORT_HTTPS || pkt.getSrcPort() == PacketParser.PORT_HTTPS) {
                sniExtractor.extractSni(pkt.getPayload(), pkt.getPayloadOffset(), pkt.getPayloadLength())
                    .ifPresent(sni -> {
                        synchronized (flow) {
                            if (flow.getSni().isEmpty()) {
                                flow.setSni(sni);
                                AppType app = appClassifier.classify(sni, pkt.getDstPort());
                                flow.setAppType(app);
                                log.debug("Flow {} → SNI: {} → App: {}", tuple, sni, app);
                            }
                        }
                    });
            }

            // HTTP Host extraction (port 80)
            if (flow.getSni().isEmpty()
                && (pkt.getDstPort() == PacketParser.PORT_HTTP || pkt.getSrcPort() == PacketParser.PORT_HTTP)) {
                sniExtractor.extractHttpHost(pkt.getPayload(), pkt.getPayloadOffset(), pkt.getPayloadLength())
                    .ifPresent(host -> {
                        synchronized (flow) {
                            if (flow.getHttpHost().isEmpty()) {
                                flow.setHttpHost(host);
                                AppType app = appClassifier.classify(host, pkt.getDstPort());
                                if (flow.getAppType() == AppType.UNKNOWN) {
                                    flow.setAppType(app);
                                }
                                log.debug("Flow {} → HTTP Host: {} → App: {}", tuple, host, app);
                            }
                        }
                    });
            }

            // Port-based fallback classification
            if (flow.getAppType() == AppType.UNKNOWN) {
                flow.setAppType(appClassifier.classify("", pkt.getDstPort()));
            }
        }

        // --- Blocking check ---
        String hostname = flow.getSni().isEmpty() ? flow.getHttpHost() : flow.getSni();
        boolean block = ruleManager.isBlocked(pkt.getSrcIp(), flow.getAppType(), hostname);

        if (block && !flow.isBlocked()) {
            synchronized (flow) { flow.setBlocked(true); }
        }

        if (flow.isBlocked()) {
            synchronized (dropped)   { dropped[0]++; }
        } else {
            synchronized (forwarded) { forwarded[0]++; }
        }
    }

    /**
     * Build the final DpiReport from flow table statistics.
     */
    private DpiReport buildReport(int totalPackets, long totalBytes, int tcpCount, int udpCount,
                                  int forwarded, int dropped,
                                  ConcurrentHashMap<FiveTuple, Flow> flowTable) {
        DpiReport report = new DpiReport();
        report.setTotalPackets(totalPackets);
        report.setTotalBytes(totalBytes);
        report.setTcpPackets(tcpCount);
        report.setUdpPackets(udpCount);
        report.setForwarded(forwarded);
        report.setDropped(dropped);

        // App breakdown
        Map<String, Long> appBreakdown = new LinkedHashMap<>();
        flowTable.values().stream()
            .collect(Collectors.groupingBy(f -> f.getAppType().name(), Collectors.summingLong(Flow::getPacketCount)))
            .entrySet().stream()
            .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
            .forEach(e -> appBreakdown.put(e.getKey(), e.getValue()));
        report.setAppBreakdown(appBreakdown);

        // Detected SNIs
        List<String> detectedSnis = flowTable.values().stream()
            .map(Flow::getSni)
            .filter(s -> !s.isEmpty())
            .distinct()
            .sorted()
            .collect(Collectors.toList());
        report.setDetectedSnis(detectedSnis);

        // Blocked flows
        List<DpiReport.BlockedFlowInfo> blockedFlows = flowTable.values().stream()
            .filter(Flow::isBlocked)
            .map(f -> {
                String sni = f.getSni().isEmpty() ? f.getHttpHost() : f.getSni();
                String reason = ruleManager.getBlockedIps().contains(f.getTuple().getSrcIp())
                    ? "IP_BLOCKED"
                    : ruleManager.getBlockedApps().contains(f.getAppType())
                        ? "APP_BLOCKED(" + f.getAppType() + ")"
                        : "DOMAIN_BLOCKED(" + sni + ")";
                return new DpiReport.BlockedFlowInfo(f.getTuple().toString(), reason, f.getPacketCount());
            })
            .collect(Collectors.toList());
        report.setBlockedFlows(blockedFlows);

        // Warnings
        List<String> warnings = new ArrayList<>();
        if (totalPackets == 0) warnings.add("No packets found in PCAP file.");
        if (dropped == 0 && !ruleManager.getBlockedApps().isEmpty()) warnings.add("Rules set but no packets were blocked — check PCAP content.");
        report.setWarnings(warnings);

        printReport(report);
        return report;
    }

    /**
     * Print a nicely-formatted report to the log (mirrors C++ console output).
     */
    private void printReport(DpiReport r) {
        log.info("╔══════════════════════════════════════╗");
        log.info("║       DPI ENGINE REPORT (Java)       ║");
        log.info("╠══════════════════════════════════════╣");
        log.info("║ Total Packets : {:>6}               ║", r.getTotalPackets());
        log.info("║ Total Bytes   : {:>6}               ║", r.getTotalBytes());
        log.info("║ TCP Packets   : {:>6}               ║", r.getTcpPackets());
        log.info("║ UDP Packets   : {:>6}               ║", r.getUdpPackets());
        log.info("║ Forwarded     : {:>6}               ║", r.getForwarded());
        log.info("║ Dropped       : {:>6}               ║", r.getDropped());
        log.info("╠══════════════════════════════════════╣");
        log.info("║ APPLICATION BREAKDOWN                 ║");
        r.getAppBreakdown().forEach((app, count) ->
            log.info("║   {:20s}: {}        ║", app, count));
        log.info("╠══════════════════════════════════════╣");
        log.info("║ DETECTED SNIs                         ║");
        r.getDetectedSnis().forEach(sni -> log.info("║   - {}                ║", sni));
        log.info("╚══════════════════════════════════════╝");
    }
}
