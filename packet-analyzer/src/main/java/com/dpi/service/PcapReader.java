package com.dpi.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * PCAP File Reader.
 * Maps to C++ PcapReader in pcap_reader.cpp
 *
 * PCAP Format:
 *   Global Header (24 bytes)
 *   [Packet Header (16 bytes) + Packet Data] * N
 */
public class PcapReader {

    private static final Logger log = LoggerFactory.getLogger(PcapReader.class);

    // PCAP magic numbers
    private static final int MAGIC_NUMBER_LE = 0xa1b2c3d4; // little-endian
    private static final int MAGIC_NUMBER_BE = 0xd4c3b2a1; // big-endian

    private static final int GLOBAL_HEADER_SIZE = 24;
    private static final int PACKET_HEADER_SIZE = 16;

    public static class RawPacket {
        public byte[] data;
        public long timestampSec;
        public long timestampUsec;
        public int capturedLen;
        public int originalLen;
    }

    /**
     * Read all raw packets from a PCAP byte array.
     */
    public List<RawPacket> readAll(byte[] pcapBytes) throws IOException {
        List<RawPacket> packets = new ArrayList<>();

        if (pcapBytes == null || pcapBytes.length < GLOBAL_HEADER_SIZE) {
            throw new IOException("Invalid PCAP: too short");
        }

        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(pcapBytes));

        // --- Read Global Header ---
        int magic = readInt32BE(dis);

        ByteOrder order;
        if (magic == MAGIC_NUMBER_LE) {
            order = ByteOrder.LITTLE_ENDIAN;
        } else if (magic == MAGIC_NUMBER_BE) {
            order = ByteOrder.BIG_ENDIAN;
        } else {
            throw new IOException("Not a valid PCAP file. Magic: 0x" + Integer.toHexString(magic));
        }

        dis.skip(20); // Skip rest of global header (version, timezone, etc.)

        log.info("PCAP file valid. Byte order: {}", order);

        // --- Read packets ---
        int count = 0;
        while (dis.available() >= PACKET_HEADER_SIZE) {
            RawPacket pkt = new RawPacket();

            if (order == ByteOrder.LITTLE_ENDIAN) {
                pkt.timestampSec  = readUint32LE(dis);
                pkt.timestampUsec = readUint32LE(dis);
                pkt.capturedLen   = (int) readUint32LE(dis);
                pkt.originalLen   = (int) readUint32LE(dis);
            } else {
                pkt.timestampSec  = readUint32BE(dis);
                pkt.timestampUsec = readUint32BE(dis);
                pkt.capturedLen   = (int) readUint32BE(dis);
                pkt.originalLen   = (int) readUint32BE(dis);
            }

            if (pkt.capturedLen <= 0 || pkt.capturedLen > 65535) {
                log.warn("Skipping packet with invalid captured length: {}", pkt.capturedLen);
                break;
            }

            if (dis.available() < pkt.capturedLen) {
                log.warn("Truncated packet at index {}", count);
                break;
            }

            pkt.data = new byte[pkt.capturedLen];
            dis.readFully(pkt.data);

            packets.add(pkt);
            count++;
        }

        log.info("Read {} packets from PCAP", count);
        return packets;
    }

    // ---- Byte reading helpers ----

    private int readInt32BE(DataInputStream dis) throws IOException {
        byte[] b = new byte[4];
        dis.readFully(b);
        return ByteBuffer.wrap(b).order(ByteOrder.BIG_ENDIAN).getInt();
    }

    private long readUint32LE(DataInputStream dis) throws IOException {
        byte[] b = new byte[4];
        dis.readFully(b);
        return Integer.toUnsignedLong(ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).getInt());
    }

    private long readUint32BE(DataInputStream dis) throws IOException {
        byte[] b = new byte[4];
        dis.readFully(b);
        return Integer.toUnsignedLong(ByteBuffer.wrap(b).order(ByteOrder.BIG_ENDIAN).getInt());
    }
}
