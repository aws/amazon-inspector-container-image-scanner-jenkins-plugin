package com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils;

import java.net.URI;
import java.net.URISyntaxException;

public class Sanitizer {
    private Sanitizer() {}

    public static String sanitizeUrl(String rawUrl) throws URISyntaxException {
        URI uri = new URI(rawUrl);
        return uri.toASCIIString();
    }

    public static String sanitizeFilePath(String rawUrl) throws URISyntaxException {
        String[] splitUrl = rawUrl.split(":");
        URI uri = new URI(splitUrl[0], splitUrl[1], null);
        return uri.toASCIIString();
    }

    public static String sanitizeText(String text) throws URISyntaxException {
        return sanitizeFilePath(text);
    }
}
