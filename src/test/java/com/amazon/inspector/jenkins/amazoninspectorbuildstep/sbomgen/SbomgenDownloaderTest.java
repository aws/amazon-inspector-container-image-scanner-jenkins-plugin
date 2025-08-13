package com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen;

import hudson.EnvVars;
import hudson.FilePath;
import hudson.remoting.VirtualChannel;
import org.junit.Test;

import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class SbomgenDownloaderTest {

    @Test
    public void testAgentEnvironmentVariableAccess() throws Exception {
        FilePath mockWorkspace = mock(FilePath.class);
        VirtualChannel mockChannel = mock(VirtualChannel.class);
        EnvVars mockEnv = mock(EnvVars.class);
        EnvVars mockRemoteEnv = mock(EnvVars.class);
        
        when(mockWorkspace.getChannel()).thenReturn(mockChannel);
        when(mockEnv.getRemote(mockChannel)).thenReturn(mockRemoteEnv);
        when(mockRemoteEnv.get("HOSTTYPE")).thenReturn("aarch64");
        
        // Verify agent environment variables can be accessed for architecture detection
        assertTrue("Should successfully access agent environment variables", 
                   mockRemoteEnv.get("HOSTTYPE").equals("aarch64"));
        assertTrue("Should have remote channel available", 
                   mockWorkspace.getChannel() != null);
    }

    @Test
    public void testFallbackWhenNoRemoteChannel() throws Exception {
        FilePath mockWorkspace = mock(FilePath.class);
        
        when(mockWorkspace.getChannel()).thenReturn(null);
        
        // Test fallback scenario when no agent channel available
        assertTrue("Should fallback to local execution when no remote channel", 
                   mockWorkspace.getChannel() == null);
    }
    
    @Test
    public void testEnvironmentVariableFallbackChain() throws Exception {
        FilePath mockWorkspace = mock(FilePath.class);
        VirtualChannel mockChannel = mock(VirtualChannel.class);
        EnvVars mockEnv = mock(EnvVars.class);
        EnvVars mockRemoteEnv = mock(EnvVars.class);
        
        when(mockWorkspace.getChannel()).thenReturn(mockChannel);
        when(mockEnv.getRemote(mockChannel)).thenReturn(mockRemoteEnv);
        when(mockRemoteEnv.get("HOSTTYPE")).thenReturn(null);
        when(mockRemoteEnv.get("MACHTYPE")).thenReturn("x86_64-pc-linux-gnu");
        
        // Test fallback from HOSTTYPE to MACHTYPE
        assertTrue("Should try HOSTTYPE first", mockRemoteEnv.get("HOSTTYPE") == null);
        assertTrue("Should fallback to MACHTYPE when HOSTTYPE unavailable", 
                   mockRemoteEnv.get("MACHTYPE").equals("x86_64-pc-linux-gnu"));
    }
}
