package com.dpi.model;

/**
 * Application type detected via Deep Packet Inspection.
 * Maps to C++ AppType enum in types.h
 */
public enum AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    GOOGLE,
    YOUTUBE,
    FACEBOOK,
    TWITTER,
    INSTAGRAM,
    TIKTOK,
    NETFLIX,
    AMAZON,
    GITHUB,
    TWITCH,
    WHATSAPP,
    TELEGRAM,
    REDDIT,
    LINKEDIN,
    ZOOM,
    DISCORD
}
