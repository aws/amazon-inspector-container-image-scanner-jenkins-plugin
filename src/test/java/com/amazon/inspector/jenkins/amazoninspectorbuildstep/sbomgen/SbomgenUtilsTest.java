package com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.AmazonInspectorBuilder;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.exception.MalformedScanOutputException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen.SbomgenUtils.processSbomgenOutput;
import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen.SbomgenUtils.stripProperties;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class SbomgenUtilsTest {

    @BeforeEach
    void setUp() {
        AmazonInspectorBuilder.setLogger(new PrintStream(new ByteArrayOutputStream()));
    }

    @Test
    void testProcessSbomgenOutput() throws MalformedScanOutputException {
        String sbom = "time=dwadaw file=wdadawdwada\n{\ntest\n}\nbdwadawdaw";
        assertEquals("{\ntest\n}", processSbomgenOutput(sbom));
    }

    @Test
    void testStripProperties() {
        String bom = "{\"components\": [{\"properties\": []}]}";
        assertFalse(stripProperties(bom).contains("\"properties\""));
    }

    @Test
    void stripProperties_returnsInputWhenComponentsMissing() {
        String bom = "{\"bomFormat\": \"CycloneDX\"}";
        assertEquals(bom, stripProperties(bom));
    }
}
