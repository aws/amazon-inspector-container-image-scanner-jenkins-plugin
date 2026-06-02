package com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen;

import hudson.FilePath;
import hudson.remoting.VirtualChannel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SbomgenRunnerTest {

    @Test
    void testIsValidPath() {
        SbomgenRunner runner = new SbomgenRunner(null, null, null, null, null, null, null, null, false);
        
        // Valid paths (matching regex: ^[a-zA-Z0-9/._\-: ]+$)
        assertTrue(runner.isValidPath("alpine:latest"));
        assertTrue(runner.isValidPath("/path/with spaces/workspace"));
        assertTrue(runner.isValidPath("/jenkins/workspace/test r7a.xlarge"));
        assertTrue(runner.isValidPath("my_image-v1.0:latest"));
        assertTrue(runner.isValidPath("/tmp/docker_image-123.tar"));
        assertTrue(runner.isValidPath("registry.example.com/namespace/image:tag"));
        
        // Test colon characters
        assertTrue(runner.isValidPath("ubuntu:22.04"));
        assertTrue(runner.isValidPath("C:/build/app.tar"));
        assertTrue(runner.isValidPath("/opt/data/container:v1.0.tar"));
        
        // Invalid paths (containing characters not in regex)
        assertFalse(runner.isValidPath("alpine:latest&&ls"));
        assertFalse(runner.isValidPath("path;rm -rf /"));
        assertFalse(runner.isValidPath("path|cat /etc/passwd"));
        assertFalse(runner.isValidPath("path$(whoami)"));
        assertFalse(runner.isValidPath("path`id`"));
        assertFalse(runner.isValidPath("path@hostname"));
    }

    @Test
    void testIsValidPathEdgeCases() {
        SbomgenRunner runner = new SbomgenRunner(null, null, null, null, null, null, null, null, false);
        
        // Edge cases that should be invalid
        assertFalse(runner.isValidPath(""));
        
        // Edge cases that should be valid
        assertTrue(runner.isValidPath("   "));
        assertTrue(runner.isValidPath("a"));
        assertTrue(runner.isValidPath("123"));
        
        // Non-existent but format-valid paths
        assertTrue(runner.isValidPath("/non/existent/path/image.tar"));
        assertTrue(runner.isValidPath("never_used_registry.com/fake:tag"));
        assertTrue(runner.isValidPath("/tmp/this_file_does_not_exist.tar"));
    }

    @Test
    void testIsValidPathWithNull() {
        SbomgenRunner runner = new SbomgenRunner(null, null, null, null, null, null, null, null, false);
        assertThrows(NullPointerException.class, () ->
            runner.isValidPath(null));
    }

    @Test
    void testWorkspaceChannelDetectionForRemoteAgent() {
        FilePath mockWorkspace = mock(FilePath.class);
        VirtualChannel mockChannel = mock(VirtualChannel.class);
        
        when(mockWorkspace.getChannel()).thenReturn(mockChannel);
        
        SbomgenRunner runner = new SbomgenRunner(null, mockWorkspace, null, null, null, null, null, null, false);
        
        // Verify the runner correctly identifies remote agent scenario
        assertNotNull(runner.getWorkspace().getChannel(), "Should detect remote agent when workspace has channel");
    }

    @Test
    void testWorkspaceChannelDetectionForLocalExecution() {
        FilePath mockWorkspace = mock(FilePath.class);
        
        when(mockWorkspace.getChannel()).thenReturn(null);
        
        SbomgenRunner runner = new SbomgenRunner(null, mockWorkspace, null, null, null, null, null, null, false);

        // Verify the runner correctly identifies local execution scenario
        assertNull(runner.getWorkspace().getChannel(), "Should detect local execution when workspace has no channel");
    }
}
