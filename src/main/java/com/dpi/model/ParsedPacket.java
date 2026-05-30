package com.dpi.model;

/**
 * Result of parsing raw packet bytes.
 * Maps to C++ ParsedPacket struct in packet_parser.h
 */
public class ParsedPacket {

    // Ethernet Layer
    private String srcMac;
    private String dstMac;
    private int etherType;  // 0x0800 = IPv4

    // IP Layer
    private String srcIp;
    private String dstIp;
    private int protocol;  // 6=TCP, 17=UDP
    private int ttl;
    private int totalLength;

    // Transport Layer
    private int srcPort;
    private int dstPort;
    private boolean hasTcp;
    private boolean hasUdp;
    private int tcpFlags;    // SYN, ACK, FIN, RST, etc.
    private int tcpSeq;
    private int tcpAck;

    // Payload
    private byte[] payload;
    private int payloadOffset;
    private int payloadLength;

    // Timestamp
    private long timestampSec;
    private long timestampUsec;

    // Valid flag
    private boolean valid;

    public ParsedPacket() {
        this.valid = false;
    }

    // ---- Getters ----
    public String getSrcMac()        { return srcMac; }
    public String getDstMac()        { return dstMac; }
    public int getEtherType()        { return etherType; }
    public String getSrcIp()         { return srcIp; }
    public String getDstIp()         { return dstIp; }
    public int getProtocol()         { return protocol; }
    public int getTtl()              { return ttl; }
    public int getTotalLength()      { return totalLength; }
    public int getSrcPort()          { return srcPort; }
    public int getDstPort()          { return dstPort; }
    public boolean isHasTcp()        { return hasTcp; }
    public boolean isHasUdp()        { return hasUdp; }
    public int getTcpFlags()         { return tcpFlags; }
    public int getTcpSeq()           { return tcpSeq; }
    public int getTcpAck()           { return tcpAck; }
    public byte[] getPayload()       { return payload; }
    public int getPayloadOffset()    { return payloadOffset; }
    public int getPayloadLength()    { return payloadLength; }
    public long getTimestampSec()    { return timestampSec; }
    public long getTimestampUsec()   { return timestampUsec; }
    public boolean isValid()         { return valid; }

    // ---- Setters ----
    public void setSrcMac(String v)       { this.srcMac = v; }
    public void setDstMac(String v)       { this.dstMac = v; }
    public void setEtherType(int v)       { this.etherType = v; }
    public void setSrcIp(String v)        { this.srcIp = v; }
    public void setDstIp(String v)        { this.dstIp = v; }
    public void setProtocol(int v)        { this.protocol = v; }
    public void setTtl(int v)             { this.ttl = v; }
    public void setTotalLength(int v)     { this.totalLength = v; }
    public void setSrcPort(int v)         { this.srcPort = v; }
    public void setDstPort(int v)         { this.dstPort = v; }
    public void setHasTcp(boolean v)      { this.hasTcp = v; }
    public void setHasUdp(boolean v)      { this.hasUdp = v; }
    public void setTcpFlags(int v)        { this.tcpFlags = v; }
    public void setTcpSeq(int v)          { this.tcpSeq = v; }
    public void setTcpAck(int v)          { this.tcpAck = v; }
    public void setPayload(byte[] v)      { this.payload = v; }
    public void setPayloadOffset(int v)   { this.payloadOffset = v; }
    public void setPayloadLength(int v)   { this.payloadLength = v; }
    public void setTimestampSec(long v)   { this.timestampSec = v; }
    public void setTimestampUsec(long v)  { this.timestampUsec = v; }
    public void setValid(boolean v)       { this.valid = v; }

    public FiveTuple toFiveTuple() {
        return new FiveTuple(srcIp, dstIp, srcPort, dstPort, protocol);
    }

    /**
     * TCP flag helpers
     */
    public boolean isSyn() { return (tcpFlags & 0x02) != 0; }
    public boolean isAck() { return (tcpFlags & 0x10) != 0; }
    public boolean isFin() { return (tcpFlags & 0x01) != 0; }
    public boolean isRst() { return (tcpFlags & 0x04) != 0; }
}
