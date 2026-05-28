package com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import org.junit.jupiter.api.Test;

import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils.Sanitizer.sanitizeFilePath;
import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils.Sanitizer.sanitizeText;
import static org.junit.jupiter.api.Assertions.assertEquals;

class SanitizerTest {

    @Test
    void testSanitizeFilePath() {
        assertEquals("file:///test%20test/%7B%7Dtest", sanitizeFilePath("file:///test test/{}test"));
    }

    @Test
    void testSanitizeNonUrl() throws URISyntaxException {
        assertEquals("test:test%7B%7D", sanitizeText("test:test{}"));
    }
}
