package com.amazon.inspector.jenkins.amazoninspectorbuildstep;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Metadata;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Property;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Sbom;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.SbomData;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomparsing.SbomOutputParser;
import hudson.model.TaskListener;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AmazonInspectorBuilderMaliciousPackageTest {
    private ByteArrayOutputStream log;
    private TaskListener listener;

    @BeforeEach
    void setUp() {
        log = new ByteArrayOutputStream();
        listener = mock(TaskListener.class);
        when(listener.getLogger()).thenReturn(new PrintStream(log, true, StandardCharsets.UTF_8));
    }

    @Test
    void doesNotFailWhenBlockingDisabled() {
        AmazonInspectorBuilder builder = builder();

        assertFalse(builder.getIsMaliciousPackageBlockingEnabled());
        assertFalse(builder.checkForMaliciousPackages(parserWithCount("2"), listener));
        assertEquals("", log.toString(StandardCharsets.UTF_8));
    }

    @Test
    void failsWhenMaliciousPackagesFound() {
        assertTrue(blockingBuilder().checkForMaliciousPackages(parserWithCount("2"), listener));
        assertTrue(log.toString(StandardCharsets.UTF_8).contains("Found 2 malicious package(s)"));
    }

    @Test
    void passesWhenNoMaliciousPackagesFound() {
        assertFalse(blockingBuilder().checkForMaliciousPackages(parserWithCount("0"), listener));
        assertTrue(log.toString(StandardCharsets.UTF_8).contains("No malicious packages found."));
    }

    @Test
    void passesWhenCountMissingFromScanResponse() {
        SbomOutputParser parser = new SbomOutputParser(SbomData.builder().sbom(Sbom.builder().build()).build());

        assertFalse(blockingBuilder().checkForMaliciousPackages(parser, listener));
        assertTrue(log.toString(StandardCharsets.UTF_8).contains("missing or unreadable"));
    }

    private static AmazonInspectorBuilder builder() {
        return new AmazonInspectorBuilder(
                "test", "test", "container", false, "", "us-east-1", "", "", "",
                "automatic", "", 0, 0, 0, 0, "", "", null, "",
                false, false, "", false, null, null);
    }

    private static AmazonInspectorBuilder blockingBuilder() {
        AmazonInspectorBuilder builder = builder();
        builder.setIsMaliciousPackageBlockingEnabled(true);
        return builder;
    }

    private static SbomOutputParser parserWithCount(String count) {
        Metadata metadata = new Metadata();
        metadata.setProperties(List.of(Property.builder()
                .name("amazon:inspector:sbom_scanner:malicious_packages")
                .value(count)
                .build()));
        return new SbomOutputParser(SbomData.builder().sbom(Sbom.builder().metadata(metadata).build()).build());
    }
}
