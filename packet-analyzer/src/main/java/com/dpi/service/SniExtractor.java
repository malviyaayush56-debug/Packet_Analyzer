package com.dpi.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * SNI (Server Name Indication) Extractor.
 * Maps to C++ SNIExtractor in sni_extractor.cpp
 *
 * --- How TLS Client Hello looks ---
 *
 * Byte 0:    Content Type = 0x16 (Handshake)
 * Bytes 1-2: TLS Version
 * Bytes 3-4: Record Length
 * Byte 5:    Handshake Type = 0x01 (Client Hello)
 * Bytes 6-8: Handshake Length
 * ...
 * Extensions:
 *   Extension Type 0x0000 = SNI
 *   → SNI Type 0x00 (hostname)
 *   → SNI Length
 *   → SNI Value: "www.youtube.com"  ← WE EXTRACT THIS!
 *
 * Even though HTTPS is encrypted, the first handshake packet
 * (Client Hello) contains the destination hostname in plaintext!
 */
@Service
public class SniExtractor {

    private static final Logger log = LoggerFactory.getLogger(SniExtractor.class);

    private static final int TLS_CONTENT_TYPE_HANDSHAKE = 0x16;
    private static final int TLS_HANDSHAKE_CLIENT_HELLO = 0x01;
    private static final int TLS_EXT_SNI = 0x0000;
    private static final int TLS_EXT_SNI_TYPE_HOST = 0x00;

    /**
     * Extract SNI hostname from TLS Client Hello payload.
     *
     * @param payload raw packet data
     * @param offset  start of TCP payload within packet
     * @param length  length of payload
     * @return Optional hostname, or empty if not found
     */
    public Optional<String> extractSni(byte[] payload, int offset, int length) {
        if (payload == null || length < 5) {
            return Optional.empty();
        }

        // --- Verify TLS Record Header ---
        // Byte 0: Content Type must be 0x16 (Handshake)
        if ((payload[offset] & 0xFF) != TLS_CONTENT_TYPE_HANDSHAKE) {
            return Optional.empty();
        }

        // Byte 5: Handshake Type must be 0x01 (Client Hello)
        if (offset + 5 >= payload.length) return Optional.empty();
        if ((payload[offset + 5] & 0xFF) != TLS_HANDSHAKE_CLIENT_HELLO) {
            return Optional.empty();
        }

        // --- Navigate Client Hello ---
        // After record header (5 bytes) + handshake header (4 bytes) = offset + 9
        // Skip Client Version (2 bytes)
        // Skip Random (32 bytes)
        // = offset + 9 + 2 + 32 = offset + 43
        int pos = offset + 43;

        if (pos >= payload.length) return Optional.empty();

        // Skip Session ID
        int sessionIdLen = payload[pos] & 0xFF;
        pos += 1 + sessionIdLen;
        if (pos + 2 >= payload.length) return Optional.empty();

        // Skip Cipher Suites
        int cipherSuitesLen = readUint16(payload, pos);
        pos += 2 + cipherSuitesLen;
        if (pos + 1 >= payload.length) return Optional.empty();

        // Skip Compression Methods
        int compMethodsLen = payload[pos] & 0xFF;
        pos += 1 + compMethodsLen;
        if (pos + 2 >= payload.length) return Optional.empty();

        // Read Extensions Length
        int extensionsLen = readUint16(payload, pos);
        pos += 2;

        int extensionsEnd = pos + extensionsLen;

        // --- Search Extensions for SNI ---
        while (pos + 4 <= extensionsEnd && pos + 4 <= payload.length) {
            int extType = readUint16(payload, pos);
            int extLen  = readUint16(payload, pos + 2);
            pos += 4;

            if (extType == TLS_EXT_SNI) {
                // SNI extension found!
                // SNI List Length: 2 bytes
                // SNI Type: 1 byte (0x00 = hostname)
                // SNI Name Length: 2 bytes
                // SNI Name: <SNI Name Length> bytes
                if (pos + 5 > payload.length) return Optional.empty();

                // Skip SNI list length (2 bytes) and SNI type (1 byte)
                int sniNameLen = readUint16(payload, pos + 3);
                int sniStart   = pos + 5;

                if (sniStart + sniNameLen > payload.length) return Optional.empty();

                String sni = new String(payload, sniStart, sniNameLen, StandardCharsets.US_ASCII);
                log.debug("Extracted SNI: {}", sni);
                return Optional.of(sni);
            }

            pos += extLen;
        }

        return Optional.empty();
    }

    /**
     * Extract HTTP Host header from plain HTTP traffic.
     *
     * @param payload raw packet data
     * @param offset  start of TCP payload
     * @param length  length of payload
     * @return Optional hostname, or empty if not HTTP
     */
    public Optional<String> extractHttpHost(byte[] payload, int offset, int length) {
        if (payload == null || length < 10) return Optional.empty();

        String payloadStr = new String(payload, offset, Math.min(length, 1024), StandardCharsets.US_ASCII);

        // Must start with an HTTP method
        if (!payloadStr.startsWith("GET ")
         && !payloadStr.startsWith("POST ")
         && !payloadStr.startsWith("HEAD ")
         && !payloadStr.startsWith("PUT ")
         && !payloadStr.startsWith("DELETE ")
         && !payloadStr.startsWith("OPTIONS ")
         && !payloadStr.startsWith("CONNECT ")) {
            return Optional.empty();
        }

        // Search for "Host: " header (case-insensitive)
        String lower = payloadStr.toLowerCase();
        int hostIdx = lower.indexOf("\r\nhost: ");
        if (hostIdx == -1) {
            hostIdx = lower.indexOf("\nhost: ");
            if (hostIdx == -1) return Optional.empty();
            hostIdx += 7;
        } else {
            hostIdx += 8;
        }

        int end = payloadStr.indexOf('\r', hostIdx);
        if (end == -1) end = payloadStr.indexOf('\n', hostIdx);
        if (end == -1) end = Math.min(hostIdx + 256, payloadStr.length());

        String host = payloadStr.substring(hostIdx, end).trim();
        // Remove port if present (e.g., "example.com:8080" → "example.com")
        int portColon = host.indexOf(':');
        if (portColon != -1) host = host.substring(0, portColon);

        log.debug("Extracted HTTP Host: {}", host);
        return host.isEmpty() ? Optional.empty() : Optional.of(host);
    }

    /** Read 2-byte big-endian unsigned integer */
    private int readUint16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }
}
