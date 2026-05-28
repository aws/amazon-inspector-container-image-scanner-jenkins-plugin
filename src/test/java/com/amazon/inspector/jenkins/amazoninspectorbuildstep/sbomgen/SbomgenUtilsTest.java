package com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen;
        
import org.junit.jupiter.api.Test;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.exception.MalformedScanOutputException;

import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen.SbomgenUtils.processSbomgenOutput;
import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen.SbomgenUtils.stripProperties;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class SbomgenUtilsTest {

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
}

