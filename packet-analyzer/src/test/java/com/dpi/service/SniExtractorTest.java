package com.dpi.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class SniExtractorTest {

    private SniExtractor extractor;

    @BeforeEach
    void setUp() {
        extractor = new SniExtractor();
    }

    /**
     * Build a minimal TLS Client Hello with SNI = "www.youtube.com"
     * This mirrors the TLS structure described in the C++ README.
     */
    @Test
    void testExtractSni_validClientHello() {
        String expectedSni = "www.youtube.com";
        byte[] payload = buildClientHello(expectedSni);

        Optional<String> result = extractor.extractSni(payload, 0, payload.length);

        assertTrue(result.isPresent(), "SNI should be extracted");
        assertEquals(expectedSni, result.get());
    }

    @Test
    void testExtractSni_notTls() {
        byte[] payload = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".getBytes();
        Optional<String> result = extractor.extractSni(payload, 0, payload.length);
        assertFalse(result.isPresent(), "Non-TLS should return empty");
    }

    @Test
    void testExtractSni_emptyPayload() {
        Optional<String> result = extractor.extractSni(new byte[0], 0, 0);
        assertFalse(result.isPresent());
    }

    @Test
    void testExtractHttpHost_validGet() {
        String raw = "GET /index.html HTTP/1.1\r\nHost: www.github.com\r\nUser-Agent: test\r\n\r\n";
        byte[] payload = raw.getBytes();

        Optional<String> result = extractor.extractHttpHost(payload, 0, payload.length);

        assertTrue(result.isPresent());
        assertEquals("www.github.com", result.get());
    }

    @Test
    void testExtractHttpHost_notHttp() {
        byte[] payload = new byte[]{0x16, 0x03, 0x01};
        Optional<String> result = extractor.extractHttpHost(payload, 0, payload.length);
        assertFalse(result.isPresent());
    }

    /**
     * Build a minimal TLS 1.2 Client Hello packet containing SNI.
     * Follows the TLS wire format described in the project README.
     */
    private byte[] buildClientHello(String sni) {
        byte[] sniBytes = sni.getBytes();
        int sniLen   = sniBytes.length;
        int extDataLen  = 2 + 1 + 2 + sniLen;  // listLen + type + nameLen + name
        int totalExtLen = 4 + extDataLen;        // type(2) + len(2) + data

        // Fixed-size fields
        int fixedPart = 43; // record(5) + handshake-hdr(4) + version(2) + random(32)
        // Session ID (1 byte len = 0)
        // Cipher suites (2 byte len + 0 bytes)
        // Compression (1 byte len + 1 byte = 0x00)
        // Extensions length (2 bytes)
        int varPart = 1 + 2 + 2 + 2;

        byte[] buf = new byte[fixedPart + varPart + totalExtLen];
        int pos = 0;

        // TLS Record Header
        buf[pos++] = 0x16;           // Content Type: Handshake
        buf[pos++] = 0x03;           // Version high
        buf[pos++] = 0x03;           // Version low (TLS 1.2)
        int recordLen = buf.length - 5;
        buf[pos++] = (byte)(recordLen >> 8);
        buf[pos++] = (byte)(recordLen & 0xFF);

        // Handshake Header
        buf[pos++] = 0x01;           // Handshake Type: Client Hello
        int hshakeLen = buf.length - 9;
        buf[pos++] = (byte)(hshakeLen >> 16);
        buf[pos++] = (byte)(hshakeLen >> 8);
        buf[pos++] = (byte)(hshakeLen & 0xFF);

        // Client Version
        buf[pos++] = 0x03;
        buf[pos++] = 0x03;

        // Random (32 bytes, all zeros for test)
        pos += 32;  // zeros already

        // Session ID Length = 0
        buf[pos++] = 0x00;

        // Cipher Suites Length = 0
        buf[pos++] = 0x00;
        buf[pos++] = 0x00;

        // Compression Methods Length = 1, value = 0
        buf[pos++] = 0x01;
        buf[pos++] = 0x00;

        // Extensions Length
        buf[pos++] = (byte)(totalExtLen >> 8);
        buf[pos++] = (byte)(totalExtLen & 0xFF);

        // SNI Extension
        // Extension Type = 0x0000
        buf[pos++] = 0x00;
        buf[pos++] = 0x00;
        // Extension Data Length
        buf[pos++] = (byte)(extDataLen >> 8);
        buf[pos++] = (byte)(extDataLen & 0xFF);
        // SNI List Length
        buf[pos++] = (byte)((extDataLen - 2) >> 8);
        buf[pos++] = (byte)((extDataLen - 2) & 0xFF);
        // SNI Type = 0x00 (hostname)
        buf[pos++] = 0x00;
        // SNI Name Length
        buf[pos++] = (byte)(sniLen >> 8);
        buf[pos++] = (byte)(sniLen & 0xFF);
        // SNI Name
        System.arraycopy(sniBytes, 0, buf, pos, sniLen);

        return buf;
    }
}
