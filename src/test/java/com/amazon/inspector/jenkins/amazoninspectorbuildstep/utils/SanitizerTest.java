package com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils;

import org.junit.Test;

import java.net.MalformedURLException;
import java.net.URISyntaxException;

import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils.Sanitizer.sanitizeFilePath;
import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils.Sanitizer.sanitizeText;
import static org.junit.Assert.assertEquals;

public class SanitizerTest {
    @Test
    public void testSanitizeFilePath() throws MalformedURLException, URISyntaxException {
        assertEquals(sanitizeFilePath("file:///test test/{}test"), "file:///test%20test/%7B%7Dtest");
    }

    @Test
    public void testSanitizeNonUrl() throws MalformedURLException, URISyntaxException {
        assertEquals(sanitizeText("test:test{}"), "test:test%7B%7D");
    }
}
