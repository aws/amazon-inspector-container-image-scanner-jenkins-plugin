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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
    void processSbomgenOutput_keepsOutermostBracesWhenBodySpansLogNoise() throws MalformedScanOutputException {
        String sbom = "time=1 file=a\n{\n\"a\": {\"b\": 1}\n}\ntime=2 file=b";
        assertEquals("{\n\"a\": {\"b\": 1}\n}", processSbomgenOutput(sbom));
    }

    @Test
    void processSbomgenOutput_throwsWhenNoBracesPresent() {
        assertThrows(MalformedScanOutputException.class,
                () -> processSbomgenOutput("time=1 file=a\nsbomgen failed to start"));
    }

    @Test
    void processSbomgenOutput_throwsWhenClosingBraceMissing() {
        assertThrows(MalformedScanOutputException.class, () -> processSbomgenOutput("{\"components\": ["));
    }

    @Test
    void processSbomgenOutput_throwsWhenBracesAreInverted() {
        assertThrows(MalformedScanOutputException.class, () -> processSbomgenOutput("}\ntest\n{"));
    }

    @Test
    void processSbomgenOutput_throwsWhenOutputIsEmpty() {
        assertThrows(MalformedScanOutputException.class, () -> processSbomgenOutput(""));
    }

    @Test
    void processSbomgenOutput_exceptionIncludesOffendingOutput() {
        String sbom = "sbomgen: permission denied";
        MalformedScanOutputException exception = assertThrows(MalformedScanOutputException.class,
                () -> processSbomgenOutput(sbom));
        assertTrue(exception.getMessage().contains(sbom));
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
