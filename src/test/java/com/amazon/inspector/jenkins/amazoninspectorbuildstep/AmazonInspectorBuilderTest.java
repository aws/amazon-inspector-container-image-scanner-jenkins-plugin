package com.amazon.inspector.jenkins.amazoninspectorbuildstep;

import org.junit.Test;

import static org.junit.Assert.*;

public class AmazonInspectorBuilderTest {

    @Test
    public void testConstructorWithLegacyParameters() {
        AmazonInspectorBuilder builder = new AmazonInspectorBuilder(
            "alpine:latest",
            "alpine:latest",
            "container",
            false,
            "",
            "us-east-1",
            "",
            "",
            "",
            "automatic",
            "",
            0, 0, 0, 0,
            "",
            "",
            0.7,
            "CVE-2023-1234,CVE-2023-5678",
            true,
            true,
            "CVE-2024-9999",
            true,                   // isThresholdEnabled (LEGACY)
            true                    // isEpssEnabled (LEGACY)
        );

        assertTrue(builder.getIsSeverityThresholdEnabled());
        assertTrue(builder.getIsEpssThresholdEnabled());
        assertTrue(builder.getIsSuppressedCveEnabled());
        assertTrue(builder.getIsAutoFailCveEnabled());
        assertEquals("CVE-2023-1234,CVE-2023-5678", builder.getSuppressedCveList());
        assertEquals("CVE-2024-9999", builder.getAutoFailCveList());
        assertEquals(Double.valueOf(0.7), builder.getEpssThreshold());
    }

    @Test
    public void testConstructorWithoutLegacy() {
        AmazonInspectorBuilder builder = new AmazonInspectorBuilder(
            "ubuntu:20.04", 
            "ubuntu:20.04", 
            "container", 
            false, 
            "", 
            "us-west-2", 
            "", 
            "", 
            "", 
            "manual", 
            "/usr/bin/sbomgen", 
            5, 10, 15, 20, 
            "", 
            "", 
            0.5, 
            "",
            false, 
            false, 
            "",
            null,
            null
        );

        assertFalse(builder.getIsSeverityThresholdEnabled());
        assertFalse(builder.getIsEpssThresholdEnabled());
        assertFalse(builder.getIsSuppressedCveEnabled());
        assertFalse(builder.getIsAutoFailCveEnabled());
        assertEquals("", builder.getSuppressedCveList());
        assertEquals("", builder.getAutoFailCveList());
        assertEquals(Double.valueOf(0.5), builder.getEpssThreshold());
        assertEquals(5, builder.getCountCritical());
        assertEquals(10, builder.getCountHigh());
        assertEquals(15, builder.getCountMedium());
        assertEquals(20, builder.getCountLow());
    }

    @Test
    public void testLegacyParameterOverride() {
        AmazonInspectorBuilder builder = new AmazonInspectorBuilder(
            "test", "test", "container", false, "", "us-east-1", "", "", "",
            "automatic", "", 0, 0, 0, 0, "", "", 0.7, "",
            false, false, "",
            true, true
        );
        
        assertTrue(builder.getIsSeverityThresholdEnabled()); 
        assertTrue(builder.getIsEpssThresholdEnabled());     
        assertFalse(builder.getIsSuppressedCveEnabled());
        assertFalse(builder.getIsAutoFailCveEnabled());
    }

    @Test
    public void testNullEpssThreshold() {
        AmazonInspectorBuilder builder = new AmazonInspectorBuilder(
            "test", "test", "container", false, "", "us-east-1", "", "", "",
            "automatic", "", 0, 0, 0, 0, "", "", null, "",
            false, false, "",
            null, null
        );
        
        assertNull(builder.getEpssThreshold());
        assertFalse(builder.getIsSeverityThresholdEnabled());
        assertFalse(builder.getIsEpssThresholdEnabled());
    }
}
