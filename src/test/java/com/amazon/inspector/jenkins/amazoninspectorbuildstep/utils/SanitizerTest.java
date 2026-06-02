package com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils;

import org.junit.jupiter.api.Test;

import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils.Sanitizer.sanitizeFilePath;
import static org.junit.jupiter.api.Assertions.assertEquals;

class SanitizerTest {

    @Test
    void testSanitizeFilePath() {
        assertEquals("file:///test%20test/%7B%7Dtest", sanitizeFilePath("file:///test test/{}test"));
    }

    @Test
    void testSanitizeNonUrl() {
        assertEquals("test:test%7B%7D", sanitizeFilePath("test:test{}"));
    }

    @Test
    void testSanitizeFilePathWithoutColon() {
        // No colon: returned as-is instead of throwing ArrayIndexOutOfBoundsException.
        assertEquals("/var/lib/jenkins/workspace/image.tar",
                sanitizeFilePath("/var/lib/jenkins/workspace/image.tar"));
    }

    @Test
    void testSanitizeEmptyString() {
        assertEquals("", sanitizeFilePath(""));
    }
}
