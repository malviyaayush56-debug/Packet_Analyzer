package com.dpi.model;

import java.util.List;
import java.util.Map;

/**
 * Final DPI analysis report.
 * Returned by the REST API after processing a PCAP file.
 */
public class DpiReport {

    private int totalPackets;
    private int tcpPackets;
    private int udpPackets;
    private long totalBytes;
    private int forwarded;
    private int dropped;

    private Map<String, Long> appBreakdown;       // AppType name -> packet count
    private List<String> detectedSnis;            // All detected SNI hostnames
    private List<BlockedFlowInfo> blockedFlows;
    private List<String> warnings;

    // ---- Inner class ----
    public static class BlockedFlowInfo {
        private final String flow;
        private final String reason;
        private final long packets;

        public BlockedFlowInfo(String flow, String reason, long packets) {
            this.flow = flow;
            this.reason = reason;
            this.packets = packets;
        }

        public String getFlow()   { return flow; }
        public String getReason() { return reason; }
        public long getPackets()  { return packets; }
    }

    // ---- Getters ----
    public int getTotalPackets()                    { return totalPackets; }
    public int getTcpPackets()                      { return tcpPackets; }
    public int getUdpPackets()                      { return udpPackets; }
    public long getTotalBytes()                     { return totalBytes; }
    public int getForwarded()                       { return forwarded; }
    public int getDropped()                         { return dropped; }
    public Map<String, Long> getAppBreakdown()      { return appBreakdown; }
    public List<String> getDetectedSnis()           { return detectedSnis; }
    public List<BlockedFlowInfo> getBlockedFlows()  { return blockedFlows; }
    public List<String> getWarnings()               { return warnings; }

    // ---- Setters ----
    public void setTotalPackets(int v)                         { this.totalPackets = v; }
    public void setTcpPackets(int v)                           { this.tcpPackets = v; }
    public void setUdpPackets(int v)                           { this.udpPackets = v; }
    public void setTotalBytes(long v)                          { this.totalBytes = v; }
    public void setForwarded(int v)                            { this.forwarded = v; }
    public void setDropped(int v)                              { this.dropped = v; }
    public void setAppBreakdown(Map<String, Long> v)           { this.appBreakdown = v; }
    public void setDetectedSnis(List<String> v)                { this.detectedSnis = v; }
    public void setBlockedFlows(List<BlockedFlowInfo> v)       { this.blockedFlows = v; }
    public void setWarnings(List<String> v)                    { this.warnings = v; }
}
