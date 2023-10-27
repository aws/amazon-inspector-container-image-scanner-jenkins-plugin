package io.jenkins.plugins.amazoninspectorbuildstep.utils;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

public class Sanitizer {
    private Sanitizer() {}

    public static String sanitizeUrl(String rawUrl) throws MalformedURLException, URISyntaxException {
        URL url = new URL(rawUrl);
        URI uri = new URI(url.getProtocol(), url.getUserInfo(), url.getHost(), url.getPort(), url.getPath(), url.getQuery(), url.getRef());
        String sanitizedUrl = uri.toURL().toString();
        sanitizedUrl = sanitizedUrl.replace("'", "%27");
        sanitizedUrl = sanitizedUrl.replace(";", "%3B");
        sanitizedUrl = sanitizedUrl.replace("(", "%28");
        sanitizedUrl = sanitizedUrl.replace(")", "%29");
        sanitizedUrl = sanitizedUrl.replace("=", "%3D");

        return sanitizedUrl.replace("file:/", "file:///");
    }

    public static String sanitizeNonUrl(String text) throws MalformedURLException, URISyntaxException {
        return sanitizeUrl("file://" + text).replace("file:///", "/");
    }
}
