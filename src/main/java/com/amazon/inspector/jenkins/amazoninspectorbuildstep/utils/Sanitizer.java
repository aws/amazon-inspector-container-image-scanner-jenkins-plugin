package com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.AmazonInspectorBuilder;

import java.net.URI;
import java.net.URISyntaxException;

public class Sanitizer {
    private Sanitizer() {}

    public static String sanitizeUrl(String rawUrl) throws URISyntaxException {
        URI uri = new URI(rawUrl);
        return uri.toASCIIString();
    }

    public static String sanitizeFilePath(String rawUrl) throws URISyntaxException {
        try {
            String[] splitUrl = rawUrl.split(":");
            URI uri = new URI(splitUrl[0], splitUrl[1], null);
            return uri.toASCIIString();
        } catch(ArrayIndexOutOfBoundsException e) {
            AmazonInspectorBuilder.logger.printf("%s in invalid format, using it as the path.", rawUrl);
            return rawUrl;
        }

    }

    public static String sanitizeText(String text) throws URISyntaxException {
        return sanitizeFilePath(text);
    }
}
