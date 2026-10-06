package com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen;

import hudson.FilePath;
import hudson.Launcher;
import hudson.model.TaskListener;
import hudson.remoting.VirtualChannel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SbomgenRunnerTest {

    @Test
    void testIsValidPath() {
        // Valid paths (matching regex: ^[a-zA-Z0-9/._\-: ]+$)
        assertTrue(SbomgenRunner.isValidPath("alpine:latest"));
        assertTrue(SbomgenRunner.isValidPath("/path/with spaces/workspace"));
        assertTrue(SbomgenRunner.isValidPath("/jenkins/workspace/test r7a.xlarge"));
        assertTrue(SbomgenRunner.isValidPath("my_image-v1.0:latest"));
        assertTrue(SbomgenRunner.isValidPath("/tmp/docker_image-123.tar"));
        assertTrue(SbomgenRunner.isValidPath("registry.example.com/namespace/image:tag"));
        
        // Test colon characters
        assertTrue(SbomgenRunner.isValidPath("ubuntu:22.04"));
        assertTrue(SbomgenRunner.isValidPath("C:/build/app.tar"));
        assertTrue(SbomgenRunner.isValidPath("/opt/data/container:v1.0.tar"));
        
        // Invalid paths (containing characters not in regex)
        assertFalse(SbomgenRunner.isValidPath("alpine:latest&&ls"));
        assertFalse(SbomgenRunner.isValidPath("path;rm -rf /"));
        assertFalse(SbomgenRunner.isValidPath("path|cat /etc/passwd"));
        assertFalse(SbomgenRunner.isValidPath("path$(whoami)"));
        assertFalse(SbomgenRunner.isValidPath("path`id`"));
        assertFalse(SbomgenRunner.isValidPath("path@hostname"));
    }

    @Test
    void testIsValidPathEdgeCases() {
        // Edge cases that should be invalid
        assertFalse(SbomgenRunner.isValidPath(""));
        
        // Edge cases that should be valid
        assertTrue(SbomgenRunner.isValidPath("   "));
        assertTrue(SbomgenRunner.isValidPath("a"));
        assertTrue(SbomgenRunner.isValidPath("123"));
        
        // Non-existent but format-valid paths
        assertTrue(SbomgenRunner.isValidPath("/non/existent/path/image.tar"));
        assertTrue(SbomgenRunner.isValidPath("never_used_registry.com/fake:tag"));
        assertTrue(SbomgenRunner.isValidPath("/tmp/this_file_does_not_exist.tar"));
    }

    @Test
    void testIsValidPathWithNull() {
        assertThrows(NullPointerException.class, () ->
            SbomgenRunner.isValidPath(null));
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

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void testRunAcceptsSbomgenInWorkspaceContainingAtSign(@TempDir Path temp) throws Exception {
        File workspace = temp.resolve("job@2").toFile();
        assertTrue(workspace.mkdirs());
        File sbomgen = new File(workspace, "inspector-sbomgen");
        Files.write(sbomgen.toPath(), "#!/bin/sh\necho '{\"components\":[]}'\n".getBytes(StandardCharsets.UTF_8));
        assertTrue(sbomgen.setExecutable(true));

        SbomgenRunner runner = new SbomgenRunner(new Launcher.LocalLauncher(TaskListener.NULL), new FilePath(workspace),
                sbomgen.getAbsolutePath(), "container", "alpine:latest", null, null, "", false);

        assertEquals("{\"components\":[]}", runner.run());
    }
}
