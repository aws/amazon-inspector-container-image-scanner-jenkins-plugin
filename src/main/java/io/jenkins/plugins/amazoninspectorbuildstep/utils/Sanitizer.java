package io.jenkins.plugins.amazoninspectorbuildstep.utils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class Sanitizer {
    private Sanitizer() {}

    public static String sanitizeUrl(String rawUrl) {
        return URLEncoder.encode(rawUrl, StandardCharsets.UTF_8).replace("%2F", "/");
    }

    public static String sanitizeNonUrl(String text) {
        return sanitizeUrl(text).replace("%3A", ":");
    }
}
