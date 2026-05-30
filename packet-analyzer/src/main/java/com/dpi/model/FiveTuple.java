package com.dpi.model;

import java.util.Objects;

/**
 * Network Five-Tuple: uniquely identifies a network connection/flow.
 * Maps to C++ FiveTuple struct in types.h
 *
 * A connection is uniquely identified by:
 *   - Source IP
 *   - Destination IP
 *   - Source Port
 *   - Destination Port
 *   - Protocol (TCP=6, UDP=17)
 */
public class FiveTuple {

    private final String srcIp;
    private final String dstIp;
    private final int srcPort;
    private final int dstPort;
    private final int protocol; // 6 = TCP, 17 = UDP

    public FiveTuple(String srcIp, String dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    public String getSrcIp()  { return srcIp; }
    public String getDstIp()  { return dstIp; }
    public int getSrcPort()   { return srcPort; }
    public int getDstPort()   { return dstPort; }
    public int getProtocol()  { return protocol; }

    public String getProtocolName() {
        return switch (protocol) {
            case 6  -> "TCP";
            case 17 -> "UDP";
            default -> "UNKNOWN(" + protocol + ")";
        };
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple ft)) return false;
        return srcPort == ft.srcPort
            && dstPort == ft.dstPort
            && protocol == ft.protocol
            && Objects.equals(srcIp, ft.srcIp)
            && Objects.equals(dstIp, ft.dstIp);
    }

    @Override
    public int hashCode() {
        return Objects.hash(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    @Override
    public String toString() {
        return srcIp + ":" + srcPort + " -> " + dstIp + ":" + dstPort + " [" + getProtocolName() + "]";
    }
}
