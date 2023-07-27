package io.jenkins.plugins.awsinspectorbuildstep.dockerutils;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.InspectImageCmd;
import com.github.dockerjava.api.command.InspectImageResponse;
import com.github.dockerjava.api.command.SaveImageCmd;
import com.github.dockerjava.api.exception.DockerClientException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

class DockerRepositoryArchiverTest {
    @Mock
    private DockerClient dockerClient;
    @Mock
    private InspectImageCmd inspectImageCmd;
    @Mock
    private InspectImageResponse inspectImageResponse;

    private File file;

    private String destinationDir;
    private String imageId;
    private PrintStream logger;
    private DockerRepositoryArchiver dockerRepositoryArchiver;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        destinationDir = "/tmp"; // Replace with your desired destination directory
        imageId = UUID.randomUUID().toString();
        logger = mock(PrintStream.class);

        file = new File("pathname");
        dockerRepositoryArchiver = spy(new DockerRepositoryArchiver(imageId, logger));
    }

    @Test
    void testArchiveRepo_Success() {
        doNothing().when(dockerRepositoryArchiver).saveRepositoryAsArchive(any(), any());

        assertEquals(dockerRepositoryArchiver.archiveRepo(file), file.getAbsolutePath());
    }

    @Test
    void testArchiveRepo_DockerClientException() {
        when(dockerClient.inspectImageCmd(imageId)).thenThrow(new DockerClientException("Docker client exception"));

        assertThrows(RuntimeException.class, () -> dockerRepositoryArchiver.archiveRepo(file));
    }

    @Test
    void testArchiveRepo_RuntimeException()  {
        when(dockerClient.inspectImageCmd(imageId)).thenReturn(inspectImageCmd);
        when(inspectImageCmd.exec()).thenReturn(inspectImageResponse);
        when(inspectImageResponse.getId()).thenReturn(imageId);

        when(dockerClient.saveImageCmd(imageId)).thenReturn(mock(SaveImageCmd.class));
        when(dockerClient.saveImageCmd(imageId).exec()).thenThrow(new RuntimeException("IO exception"));

        assertThrows(RuntimeException.class, () -> dockerRepositoryArchiver.archiveRepo(file));
    }

    @Test
    void testSaveRepositoryAsArchive_RuntimeException() throws IOException {
        SaveImageCmd mockSaveImageCmd = mock(SaveImageCmd.class);
        InputStream mockStream = mock(InputStream.class);
        when(mockSaveImageCmd.exec()).thenReturn(mockStream);
        when(mockStream.read(any())).thenThrow(FileNotFoundException.class);

        assertThrows(RuntimeException.class, () -> dockerRepositoryArchiver.saveRepositoryAsArchive(
                dockerClient, new File("")));
    }
}