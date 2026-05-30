package com.dpi.service;

import com.dpi.model.AppType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class AppClassifierTest {

    private AppClassifier classifier;
    private RuleManager ruleManager;

    @BeforeEach
    void setUp() {
        classifier = new AppClassifier();
        ruleManager = new RuleManager();
    }

    @Test
    void testYoutube() {
        assertEquals(AppType.YOUTUBE, classifier.classify("www.youtube.com", 443));
        assertEquals(AppType.YOUTUBE, classifier.classify("youtu.be", 443));
        assertEquals(AppType.YOUTUBE, classifier.classify("i.ytimg.com", 443));
    }

    @Test
    void testFacebook() {
        assertEquals(AppType.FACEBOOK, classifier.classify("www.facebook.com", 443));
        assertEquals(AppType.FACEBOOK, classifier.classify("static.xx.fbcdn.net", 443));
    }

    @Test
    void testGoogle() {
        assertEquals(AppType.GOOGLE, classifier.classify("www.google.com", 443));
        assertEquals(AppType.GOOGLE, classifier.classify("fonts.googleapis.com", 443));
    }

    @Test
    void testFallbackByPort() {
        assertEquals(AppType.HTTP,  classifier.classify("", 80));
        assertEquals(AppType.HTTPS, classifier.classify("", 443));
        assertEquals(AppType.DNS,   classifier.classify("", 53));
        assertEquals(AppType.UNKNOWN, classifier.classify("", 9999));
    }

    @Test
    void testBlockByIp() {
        ruleManager.addBlockedIp("192.168.1.50");
        assertTrue(ruleManager.isBlocked("192.168.1.50", AppType.UNKNOWN, ""));
        assertFalse(ruleManager.isBlocked("192.168.1.51", AppType.UNKNOWN, ""));
    }

    @Test
    void testBlockByApp() {
        ruleManager.addBlockedApp(AppType.YOUTUBE);
        assertTrue(ruleManager.isBlocked("10.0.0.1", AppType.YOUTUBE, "www.youtube.com"));
        assertFalse(ruleManager.isBlocked("10.0.0.1", AppType.GOOGLE, "www.google.com"));
    }

    @Test
    void testBlockByDomain() {
        ruleManager.addBlockedDomain("tiktok");
        assertTrue(ruleManager.isBlocked("10.0.0.1", AppType.TIKTOK, "www.tiktok.com"));
        assertTrue(ruleManager.isBlocked("10.0.0.1", AppType.UNKNOWN, "api.tiktok.com"));
        assertFalse(ruleManager.isBlocked("10.0.0.1", AppType.YOUTUBE, "www.youtube.com"));
    }

    @Test
    void testClearRules() {
        ruleManager.addBlockedApp(AppType.YOUTUBE);
        ruleManager.clearAll();
        assertFalse(ruleManager.isBlocked("10.0.0.1", AppType.YOUTUBE, "www.youtube.com"));
    }
}
