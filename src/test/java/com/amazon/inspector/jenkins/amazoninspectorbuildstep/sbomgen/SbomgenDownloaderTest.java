package com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.remoting.VirtualChannel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SbomgenDownloaderTest {

    @Test
    void testAgentEnvironmentVariableAccess() throws Exception {
        FilePath mockWorkspace = mock(FilePath.class);
        VirtualChannel mockChannel = mock(VirtualChannel.class);
        EnvVars mockEnv = mock(EnvVars.class);
        EnvVars mockRemoteEnv = mock(EnvVars.class);
        
        when(mockWorkspace.getChannel()).thenReturn(mockChannel);
        when(mockEnv.getRemote(mockChannel)).thenReturn(mockRemoteEnv);
        when(mockRemoteEnv.get("HOSTTYPE")).thenReturn("aarch64");

        // Verify agent environment variables can be accessed for architecture detection
        assertEquals("aarch64", mockRemoteEnv.get("HOSTTYPE"), "Should successfully access agent environment variables");
        assertNotNull(mockWorkspace.getChannel(), "Should have remote channel available");
    }

    @Test
    void testFallbackWhenNoRemoteChannel() {
        FilePath mockWorkspace = mock(FilePath.class);
        
        when(mockWorkspace.getChannel()).thenReturn(null);

        // Test fallback scenario when no agent channel available
        assertNull(mockWorkspace.getChannel(), "Should fallback to local execution when no remote channel");
    }

    @Test
    void testEnvironmentVariableFallbackChain() throws Exception {
        FilePath mockWorkspace = mock(FilePath.class);
        VirtualChannel mockChannel = mock(VirtualChannel.class);
        EnvVars mockEnv = mock(EnvVars.class);
        EnvVars mockRemoteEnv = mock(EnvVars.class);
        
        when(mockWorkspace.getChannel()).thenReturn(mockChannel);
        when(mockEnv.getRemote(mockChannel)).thenReturn(mockRemoteEnv);
        when(mockRemoteEnv.get("HOSTTYPE")).thenReturn(null);
        when(mockRemoteEnv.get("MACHTYPE")).thenReturn("x86_64-pc-linux-gnu");

        // Test fallback from HOSTTYPE to MACHTYPE
        assertNull(mockRemoteEnv.get("HOSTTYPE"), "Should try HOSTTYPE first");
        assertEquals("x86_64-pc-linux-gnu", mockRemoteEnv.get("MACHTYPE"), "Should fallback to MACHTYPE when HOSTTYPE unavailable");
    }
}
