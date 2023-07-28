package io.jenkins.plugins.awsinspectorbuildstep.dockerutils;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.SaveImageCmd;
import com.github.dockerjava.api.exception.DockerClientException;
import com.google.common.annotations.VisibleForTesting;
import lombok.AllArgsConstructor;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;

import static com.github.dockerjava.core.DockerClientBuilder.getInstance;

@AllArgsConstructor
public class DockerRepositoryArchiver {
    private String imageId;
    private PrintStream logger;

    public String archiveRepo(File destinationFile) {
        try (DockerClient dockerClient = getInstance().build()) {
            saveRepositoryAsArchive(dockerClient, destinationFile);

            return destinationFile.getAbsolutePath();
        } catch (IOException | DockerClientException e) {
            throw new RuntimeException(e);
        }
    }

    @VisibleForTesting
    protected void saveRepositoryAsArchive(DockerClient dockerClient, File destinationFile) {
        logger.println("Saving repo to archive");

        try (OutputStream outputStream = new FileOutputStream(destinationFile)) {
            SaveImageCmd saveImageCmd = dockerClient.saveImageCmd(imageId);
            InputStream inputStream = saveImageCmd.exec();
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }

            logger.println("Repository saved as a tarball archive successfully.");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public File createArchiveDestination(String destinationDirName) {
        String destinationPath = String.format("%s/%s.tar", destinationDirName, imageId);
        logger.printf("Got destination path %s", destinationPath);

        File destinationFile = new File(destinationPath);
        destinationFile.getParentFile().mkdirs();

        logger.printf("Saving archive to %s", destinationFile);

        return destinationFile;
    }
}
