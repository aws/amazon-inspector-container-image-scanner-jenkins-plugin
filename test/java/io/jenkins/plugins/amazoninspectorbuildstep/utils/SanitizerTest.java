package io.jenkins.plugins.amazoninspectorbuildstep.utils;

import org.junit.Test;

import java.net.MalformedURLException;
import java.net.URISyntaxException;

import static io.jenkins.plugins.amazoninspectorbuildstep.utils.Sanitizer.sanitizeNonUrl;
import static io.jenkins.plugins.amazoninspectorbuildstep.utils.Sanitizer.sanitizeUrl;
import static org.junit.Assert.assertEquals;

public class SanitizerTest {
    @Test
    public void testSanitizeUrl() throws MalformedURLException, URISyntaxException {
        assertEquals(sanitizeUrl("file:///test test/{}test"), "file:///test%20test/7B%7Dtest");
    }

    @Test
    public void testSanitizeNonUrl() throws MalformedURLException, URISyntaxException {
        assertEquals(sanitizeNonUrl("test:test{}"), "test:test%7B%7D");
    }
}
