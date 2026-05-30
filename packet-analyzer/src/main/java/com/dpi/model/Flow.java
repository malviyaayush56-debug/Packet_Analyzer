package com.dpi.model;

import java.time.Instant;

/**
 * Represents a tracked network flow (connection).
 * Maps to C++ Flow struct.
 *
 * All packets with the same FiveTuple belong to this flow.
 * Once blocked, all subsequent packets of this flow are dropped.
 */
public class Flow {

    private final FiveTuple tuple;
    private AppType appType = AppType.UNKNOWN;
    private String sni = "";       // Extracted from TLS Client Hello
    private String httpHost = "";  // Extracted from HTTP Host header
    private boolean blocked = false;
    private long packetCount = 0;
    private long byteCount = 0;
    private Instant firstSeen;
    private Instant lastSeen;

    public Flow(FiveTuple tuple) {
        this.tuple = tuple;
        this.firstSeen = Instant.now();
        this.lastSeen = Instant.now();
    }

    public void addPacket(int bytes) {
        packetCount++;
        byteCount += bytes;
        lastSeen = Instant.now();
    }

    // Getters
    public FiveTuple getTuple()    { return tuple; }
    public AppType getAppType()    { return appType; }
    public String getSni()         { return sni; }
    public String getHttpHost()    { return httpHost; }
    public boolean isBlocked()     { return blocked; }
    public long getPacketCount()   { return packetCount; }
    public long getByteCount()     { return byteCount; }
    public Instant getFirstSeen()  { return firstSeen; }
    public Instant getLastSeen()   { return lastSeen; }

    // Setters
    public void setAppType(AppType appType) { this.appType = appType; }
    public void setSni(String sni)          { this.sni = sni; }
    public void setHttpHost(String host)    { this.httpHost = host; }
    public void setBlocked(boolean blocked) { this.blocked = blocked; }

    @Override
    public String toString() {
        return "Flow{" + tuple + ", app=" + appType + ", sni='" + sni + "', blocked=" + blocked + "}";
    }
}
