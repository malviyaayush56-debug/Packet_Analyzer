package com.dpi.service;

import com.dpi.model.AppType;
import org.springframework.stereotype.Service;

/**
 * Application Classifier.
 * Maps SNI hostname or HTTP Host to an AppType.
 * Maps to C++ sniToAppType() in types.cpp
 */
@Service
public class AppClassifier {

    /**
     * Classify a hostname into an AppType.
     *
     * @param hostname SNI or HTTP Host header value
     * @param dstPort  destination port (for basic classification fallback)
     * @return classified AppType
     */
    public AppType classify(String hostname, int dstPort) {
        if (hostname == null || hostname.isBlank()) {
            return fallbackByPort(dstPort);
        }

        String h = hostname.toLowerCase();

        // YouTube
        if (h.contains("youtube") || h.contains("youtu.be")
            || h.contains("ytimg") || h.contains("yt3.ggpht")) {
            return AppType.YOUTUBE;
        }
        // Google
        if (h.contains("google") || h.contains("googleapis")
            || h.contains("gstatic") || h.contains("googleusercontent")) {
            return AppType.GOOGLE;
        }
        // Facebook / Instagram (Meta)
        if (h.contains("facebook") || h.contains("fbcdn")
            || h.contains("fb.com") || h.contains("fb.net")) {
            return AppType.FACEBOOK;
        }
        if (h.contains("instagram") || h.contains("cdninstagram")) {
            return AppType.INSTAGRAM;
        }
        // Twitter / X
        if (h.contains("twitter") || h.contains("twimg")
            || h.contains("x.com")) {
            return AppType.TWITTER;
        }
        // TikTok
        if (h.contains("tiktok") || h.contains("tiktokcdn")
            || h.contains("muscdn")) {
            return AppType.TIKTOK;
        }
        // Netflix
        if (h.contains("netflix") || h.contains("nflximg")
            || h.contains("nflxvideo")) {
            return AppType.NETFLIX;
        }
        // Amazon
        if (h.contains("amazon") || h.contains("amazonaws")
            || h.contains("cloudfront")) {
            return AppType.AMAZON;
        }
        // GitHub
        if (h.contains("github") || h.contains("githubusercontent")
            || h.contains("githubassets")) {
            return AppType.GITHUB;
        }
        // Twitch
        if (h.contains("twitch") || h.contains("twitchsvc")) {
            return AppType.TWITCH;
        }
        // WhatsApp
        if (h.contains("whatsapp")) {
            return AppType.WHATSAPP;
        }
        // Telegram
        if (h.contains("telegram") || h.contains("t.me")) {
            return AppType.TELEGRAM;
        }
        // Reddit
        if (h.contains("reddit") || h.contains("redd.it")
            || h.contains("reddituserdata") || h.contains("redditmedia")) {
            return AppType.REDDIT;
        }
        // LinkedIn
        if (h.contains("linkedin")) {
            return AppType.LINKEDIN;
        }
        // Zoom
        if (h.contains("zoom.us") || h.contains("zoom.com")) {
            return AppType.ZOOM;
        }
        // Discord
        if (h.contains("discord") || h.contains("discordapp")) {
            return AppType.DISCORD;
        }

        return fallbackByPort(dstPort);
    }

    private AppType fallbackByPort(int port) {
        return switch (port) {
            case 80   -> AppType.HTTP;
            case 443  -> AppType.HTTPS;
            case 53   -> AppType.DNS;
            default   -> AppType.UNKNOWN;
        };
    }
}
