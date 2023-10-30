package io.jenkins.plugins.amazoninspectorbuildstep.bomerman;

import org.junit.Test;

import static io.jenkins.plugins.amazoninspectorbuildstep.bomerman.BomermanRunner.stripProperties;
import static org.junit.Assert.assertFalse;

public class BomermanRunnerTest {
    @Test
    public void testStripProperties() {
        String bom = "{\"components\": [{\"properties\": []}]}";
        assertFalse(stripProperties(bom).contains("\"properties\""));
    }
}
