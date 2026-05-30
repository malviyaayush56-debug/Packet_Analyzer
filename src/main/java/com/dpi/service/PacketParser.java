package com.dpi.service;

import com.dpi.model.ParsedPacket;
import com.dpi.service.PcapReader.RawPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * Network Packet Parser.
 * Maps to C++ PacketParser in packet_parser.cpp
 *
 * Parses raw bytes → Ethernet → IP → TCP/UDP headers.
 *
 * Packet structure (Russian nesting doll):
 *   [Ethernet 14B][IP 20B][TCP/UDP 20/8B][Payload...]
 */
@Service
public class PacketParser {

    private static final Logger log = LoggerFactory.getLogger(PacketParser.class);

    // EtherType values
    private static final int ETHERTYPE_IPV4 = 0x0800;

    // IP Protocol numbers
    private static final int PROTO_TCP = 6;
    private static final int PROTO_UDP = 17;

    // Well-known ports
    public static final int PORT_HTTP  = 80;
    public static final int PORT_HTTPS = 443;
    public static final int PORT_DNS   = 53;

    /**
     * Parse a raw PCAP packet into structured fields.
     */
    public ParsedPacket parse(RawPacket raw) {
        ParsedPacket pkt = new ParsedPacket();
        pkt.setTimestampSec(raw.timestampSec);
        pkt.setTimestampUsec(raw.timestampUsec);

        byte[] data = raw.data;

        if (data == null || data.length < 14) {
            log.debug("Packet too short for Ethernet header: {} bytes", data == null ? 0 : data.length);
            return pkt;
        }

        // --- Ethernet Header (14 bytes) ---
        // Bytes 0-5:   Destination MAC
        // Bytes 6-11:  Source MAC
        // Bytes 12-13: EtherType
        pkt.setDstMac(formatMac(data, 0));
        pkt.setSrcMac(formatMac(data, 6));
        int etherType = readUint16(data, 12);
        pkt.setEtherType(etherType);

        if (etherType != ETHERTYPE_IPV4) {
            log.debug("Non-IPv4 packet (EtherType=0x{}) — skipping", Integer.toHexString(etherType));
            return pkt;
        }

        if (data.length < 34) {
            log.debug("Packet too short for IP header");
            return pkt;
        }

        // --- IPv4 Header (20+ bytes, starts at offset 14) ---
        int ipStart = 14;
        int ipVerIhl = data[ipStart] & 0xFF;
        // int ipVersion = (ipVerIhl >> 4) & 0xF;  // should be 4
        int ipHeaderLen = (ipVerIhl & 0x0F) * 4;  // in bytes

        pkt.setTtl(data[ipStart + 8] & 0xFF);
        int protocol = data[ipStart + 9] & 0xFF;
        pkt.setProtocol(protocol);

        int totalLength = readUint16(data, ipStart + 2);
        pkt.setTotalLength(totalLength);

        // Source IP: bytes 12-15 of IP header
        pkt.setSrcIp(formatIp(data, ipStart + 12));
        // Destination IP: bytes 16-19 of IP header
        pkt.setDstIp(formatIp(data, ipStart + 16));

        int transportStart = ipStart + ipHeaderLen;

        // --- TCP Header ---
        if (protocol == PROTO_TCP) {
            if (data.length < transportStart + 20) {
                log.debug("Packet too short for TCP header");
                return pkt;
            }
            pkt.setHasTcp(true);
            pkt.setSrcPort(readUint16(data, transportStart));
            pkt.setDstPort(readUint16(data, transportStart + 2));
            pkt.setTcpSeq((int) readUint32(data, transportStart + 4));
            pkt.setTcpAck((int) readUint32(data, transportStart + 8));

            int dataOffset = ((data[transportStart + 12] & 0xFF) >> 4) * 4; // TCP header length
            pkt.setTcpFlags(data[transportStart + 13] & 0xFF);

            int payloadStart = transportStart + dataOffset;
            int payloadLen = Math.max(0, data.length - payloadStart);
            pkt.setPayload(data);
            pkt.setPayloadOffset(payloadStart);
            pkt.setPayloadLength(payloadLen);
        }
        // --- UDP Header ---
        else if (protocol == PROTO_UDP) {
            if (data.length < transportStart + 8) {
                log.debug("Packet too short for UDP header");
                return pkt;
            }
            pkt.setHasUdp(true);
            pkt.setSrcPort(readUint16(data, transportStart));
            pkt.setDstPort(readUint16(data, transportStart + 2));

            int payloadStart = transportStart + 8;
            int payloadLen = Math.max(0, data.length - payloadStart);
            pkt.setPayload(data);
            pkt.setPayloadOffset(payloadStart);
            pkt.setPayloadLength(payloadLen);
        } else {
            log.debug("Unsupported transport protocol: {}", protocol);
        }

        pkt.setValid(true);
        return pkt;
    }

    // ---- Byte Parsing Utilities ----

    /** Read 2-byte big-endian unsigned integer */
    private int readUint16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    /** Read 4-byte big-endian unsigned integer */
    private long readUint32(byte[] data, int offset) {
        return ((long)(data[offset] & 0xFF) << 24)
             | ((long)(data[offset+1] & 0xFF) << 16)
             | ((long)(data[offset+2] & 0xFF) << 8)
             | ((long)(data[offset+3] & 0xFF));
    }

    /** Format 6 bytes as MAC address: XX:XX:XX:XX:XX:XX */
    private String formatMac(byte[] data, int offset) {
        return String.format("%02x:%02x:%02x:%02x:%02x:%02x",
            data[offset]   & 0xFF, data[offset+1] & 0xFF,
            data[offset+2] & 0xFF, data[offset+3] & 0xFF,
            data[offset+4] & 0xFF, data[offset+5] & 0xFF);
    }

    /** Format 4 bytes as IPv4 address: A.B.C.D */
    private String formatIp(byte[] data, int offset) {
        return (data[offset] & 0xFF) + "."
             + (data[offset+1] & 0xFF) + "."
             + (data[offset+2] & 0xFF) + "."
             + (data[offset+3] & 0xFF);
    }
}
