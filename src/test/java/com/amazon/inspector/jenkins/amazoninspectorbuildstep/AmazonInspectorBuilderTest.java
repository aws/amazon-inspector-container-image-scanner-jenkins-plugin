package com.amazon.inspector.jenkins.amazoninspectorbuildstep;

import org.junit.Test;

import static org.junit.Assert.*;

public class AmazonInspectorBuilderTest {

    @Test
    public void testConstructorWithNewParameters() {
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
            true, 
            true, 
            "CVE-2024-9999"
        );

        assertTrue(builder.getIsSeverityThresholdEnabled());
        assertTrue(builder.getIsEpssThresholdEnabled());
        assertTrue(builder.getIsSuppressedCveEnabled());
        assertTrue(builder.getIsAutoFailCveEnabled());
        assertEquals("CVE-2023-1234,CVE-2023-5678", builder.getSuppressedCves());
        assertEquals("CVE-2024-9999", builder.getAutoFailCves());
        assertEquals(Double.valueOf(0.7), builder.getEpssThreshold());
    }

    @Test
    public void testConstructorWithFalseFlags() {
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
            false, 
            false, 
            ""
        );

        assertFalse(builder.getIsSeverityThresholdEnabled());
        assertFalse(builder.getIsEpssThresholdEnabled());
        assertFalse(builder.getIsSuppressedCveEnabled());
        assertFalse(builder.getIsAutoFailCveEnabled());
        assertEquals("", builder.getSuppressedCves());
        assertEquals("", builder.getAutoFailCves());
        assertEquals(Double.valueOf(0.5), builder.getEpssThreshold());
        assertEquals(5, builder.getCountCritical());
        assertEquals(10, builder.getCountHigh());
        assertEquals(15, builder.getCountMedium());
        assertEquals(20, builder.getCountLow());
    }

    @Test
    public void testGettersReturnCorrectValues() {
        AmazonInspectorBuilder builder = new AmazonInspectorBuilder(
            "test-image:v1.0", 
            "", 
            "container", 
            true, 
            "test-role", 
            "eu-west-1", 
            "cred-id", 
            "profile", 
            "aws-cred", 
            "automatic", 
            "", 
            1, 2, 3, 4, 
            "oidc-id", 
            "*.log", 
            0.8, 
            "CVE-2023-1111",
            true, 
            true, 
            true, 
            true, 
            "CVE-2023-2222"
        );

        assertEquals("test-image:v1.0", builder.getArchivePath());
        assertEquals("container", builder.getArchiveType());
        assertTrue(builder.isOsArch());
        assertEquals("test-role", builder.getIamRole());
        assertEquals("eu-west-1", builder.getAwsRegion());
        assertEquals("cred-id", builder.getCredentialId());
        assertEquals("profile", builder.getAwsProfileName());
        assertEquals("aws-cred", builder.getAwsCredentialId());
        assertEquals("automatic", builder.getSbomgenSelection());
        assertEquals("", builder.getSbomgenPath());
        assertEquals(1, builder.getCountCritical());
        assertEquals(2, builder.getCountHigh());
        assertEquals(3, builder.getCountMedium());
        assertEquals(4, builder.getCountLow());
        assertEquals("oidc-id", builder.getOidcCredentialId());
        assertEquals("*.log", builder.getSbomgenSkipFiles());
        assertEquals(Double.valueOf(0.8), builder.getEpssThreshold());
        assertEquals("CVE-2023-1111", builder.getSuppressedCves());
        assertEquals("CVE-2023-2222", builder.getAutoFailCves());
    }

    @Test
    public void testNullEpssThreshold() {
        AmazonInspectorBuilder builder = new AmazonInspectorBuilder(
            "test", "test", "container", false, "", "us-east-1", "", "", "",
            "automatic", "", 0, 0, 0, 0, "", "", null, "",
            false, false, false, false, ""
        );
        
        assertNull(builder.getEpssThreshold());
    }

    @Test
    public void testEmptyStringParameters() {
        AmazonInspectorBuilder builder = new AmazonInspectorBuilder(
            "", "", "container", false, "", "us-east-1", "", "", "",
            "automatic", "", 0, 0, 0, 0, "", "", 0.0, "",
            false, false, false, false, ""
        );
        
        assertEquals("", builder.getArchivePath());
        assertEquals("", builder.getSuppressedCves());
        assertEquals("", builder.getAutoFailCves());
        assertEquals(Double.valueOf(0.0), builder.getEpssThreshold());
    }

    @Test
    public void testBoundaryValueThresholds() {
        AmazonInspectorBuilder builder = new AmazonInspectorBuilder(
            "test", "test", "container", false, "", "us-east-1", "", "", "",
            "automatic", "", Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MAX_VALUE, Integer.MAX_VALUE,
            "", "", 1.0, "",
            true, true, false, false, ""
        );
        
        assertEquals(Integer.MAX_VALUE, builder.getCountCritical());
        assertEquals(Integer.MAX_VALUE, builder.getCountHigh());
        assertEquals(Integer.MAX_VALUE, builder.getCountMedium());
        assertEquals(Integer.MAX_VALUE, builder.getCountLow());
        assertEquals(Double.valueOf(1.0), builder.getEpssThreshold());
    }

    @Test
    public void testZeroThresholds() {
        AmazonInspectorBuilder builder = new AmazonInspectorBuilder(
            "test", "test", "container", false, "", "us-east-1", "", "", "",
            "automatic", "", 0, 0, 0, 0,
            "", "", 0.0, "",
            true, true, false, false, ""
        );
        
        assertEquals(0, builder.getCountCritical());
        assertEquals(0, builder.getCountHigh());
        assertEquals(0, builder.getCountMedium());
        assertEquals(0, builder.getCountLow());
        assertEquals(Double.valueOf(0.0), builder.getEpssThreshold());
    }

    @Test
    public void testMixedFeatureFlags() {
        AmazonInspectorBuilder builder = new AmazonInspectorBuilder(
            "alpine:3.18", "alpine:3.18", "container", true, "arn:aws:iam::123456789012:role/test", 
            "ap-southeast-1", "jenkins-cred", "dev-profile", "aws-cred-123",
            "manual", "/custom/path/sbomgen", 1, 5, 10, 50,
            "oidc-123", "*.tmp,*.log", 0.85, "CVE-2023-1111,CVE-2023-2222",
            true, false, true, false, "CVE-2023-9999"
        );
        
        assertTrue(builder.getIsSeverityThresholdEnabled());
        assertFalse(builder.getIsEpssThresholdEnabled());
        assertTrue(builder.getIsSuppressedCveEnabled());
        assertFalse(builder.getIsAutoFailCveEnabled());
        assertEquals("CVE-2023-1111,CVE-2023-2222", builder.getSuppressedCves());
        assertEquals("CVE-2023-9999", builder.getAutoFailCves());
        assertEquals("/custom/path/sbomgen", builder.getSbomgenPath());
        assertEquals("manual", builder.getSbomgenSelection());
        assertTrue(builder.isOsArch());
    }

    @Test
    public void testComplexCveStrings() {
        AmazonInspectorBuilder builder = new AmazonInspectorBuilder(
            "test", "test", "container", false, "", "us-east-1", "", "", "",
            "automatic", "", 0, 0, 0, 0, "", "", 0.5,
            "CVE-2023-1234,CVE-2024-5678,CVE-2022-9999,CVE-2025-123456",
            true, true, true, true,
            "CVE-2023-0001,CVE-2024-0002"
        );
        
        assertEquals("CVE-2023-1234,CVE-2024-5678,CVE-2022-9999,CVE-2025-123456", builder.getSuppressedCves());
        assertEquals("CVE-2023-0001,CVE-2024-0002", builder.getAutoFailCves());
    }

    @Test
    public void testSingleCveStrings() {
        AmazonInspectorBuilder builder = new AmazonInspectorBuilder(
            "test", "test", "container", false, "", "us-east-1", "", "", "",
            "automatic", "", 0, 0, 0, 0, "", "", 0.5,
            "CVE-2023-1234",
            true, true, true, true,
            "CVE-2024-9999"
        );
        
        assertEquals("CVE-2023-1234", builder.getSuppressedCves());
        assertEquals("CVE-2024-9999", builder.getAutoFailCves());
    }

    @Test
    public void testAllArchiveTypes() {
        AmazonInspectorBuilder containerBuilder = new AmazonInspectorBuilder(
            "test", "test", "container", false, "", "us-east-1", "", "", "",
            "automatic", "", 0, 0, 0, 0, "", "", null, "",
            false, false, false, false, ""
        );
        assertEquals("container", containerBuilder.getArchiveType());

        AmazonInspectorBuilder archiveBuilder = new AmazonInspectorBuilder(
            "test", "test", "archive", false, "", "us-east-1", "", "", "",
            "automatic", "", 0, 0, 0, 0, "", "", null, "",
            false, false, false, false, ""
        );
        assertEquals("archive", archiveBuilder.getArchiveType());
    }

    @Test
    public void testAllRegions() {
        String[] regions = {"us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "ca-central-1"};
        
        for (String region : regions) {
            AmazonInspectorBuilder builder = new AmazonInspectorBuilder(
                "test", "test", "container", false, "", region, "", "", "",
                "automatic", "", 0, 0, 0, 0, "", "", null, "",
                false, false, false, false, ""
            );
            assertEquals(region, builder.getAwsRegion());
        }
    }

    @Test
    public void testSbomgenSelectionOptions() {
        String[] selections = {"automatic", "manual"};
        
        for (String selection : selections) {
            AmazonInspectorBuilder builder = new AmazonInspectorBuilder(
                "test", "test", "container", false, "", "us-east-1", "", "", "",
                selection, "", 0, 0, 0, 0, "", "", null, "",
                false, false, false, false, ""
            );
            assertEquals(selection, builder.getSbomgenSelection());
        }
    }

    @Test
    public void testFeatureFlagCombinations() {
        boolean[] flags = {true, false};
        
        for (boolean severityFlag : flags) {
            for (boolean epssFlag : flags) {
                for (boolean suppressFlag : flags) {
                    for (boolean autoFailFlag : flags) {
                        AmazonInspectorBuilder builder = new AmazonInspectorBuilder(
                            "test", "test", "container", false, "", "us-east-1", "", "", "",
                            "automatic", "", 0, 0, 0, 0, "", "", 0.5, "",
                            severityFlag, epssFlag, suppressFlag, autoFailFlag, ""
                        );
                        
                        assertEquals(severityFlag, builder.getIsSeverityThresholdEnabled());
                        assertEquals(epssFlag, builder.getIsEpssThresholdEnabled());
                        assertEquals(suppressFlag, builder.getIsSuppressedCveEnabled());
                        assertEquals(autoFailFlag, builder.getIsAutoFailCveEnabled());
                    }
                }
            }
        }
    }

    @Test
    public void testSpecialCharactersInPaths() {
        AmazonInspectorBuilder builder = new AmazonInspectorBuilder(
            "/path with spaces/image-name_v1.0:latest", 
            "/path with spaces/image-name_v1.0:latest", 
            "container", 
            false, 
            "", 
            "us-east-1", 
            "", 
            "", 
            "",
            "automatic", 
            "/usr/bin/sbomgen-tool_v2", 
            0, 0, 0, 0, 
            "", 
            "*.tmp *.log", 
            null, 
            "",
            false, false, false, false, ""
        );
        
        assertEquals("/path with spaces/image-name_v1.0:latest", builder.getArchivePath());
        assertEquals("/usr/bin/sbomgen-tool_v2", builder.getSbomgenPath());
        assertEquals("*.tmp *.log", builder.getSbomgenSkipFiles());
    }
}
