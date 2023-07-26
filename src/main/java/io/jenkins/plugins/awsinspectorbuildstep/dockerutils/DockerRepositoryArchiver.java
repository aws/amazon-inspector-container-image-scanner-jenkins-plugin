package io.jenkins.plugins.awsinspectorbuildstep.dockerutils;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.InspectImageResponse;
import com.github.dockerjava.api.command.SaveImageCmd;
import com.github.dockerjava.api.exception.DockerClientException;
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
    String destinationDir;
    String imageId;
    PrintStream logger;

    public String archiveRepo() {
        String destinationPath = String.format("%s/%s.tar", destinationDir, imageId);
        logger.printf("Got destination path %s", destinationPath);

        try (DockerClient dockerClient = getInstance().build()) {
            InspectImageResponse response = dockerClient.inspectImageCmd(imageId).exec();
            return saveRepositoryAsArchive(dockerClient, response.getId(), destinationPath);
        } catch (IOException | DockerClientException e) {
            e.printStackTrace();
        }
        return destinationPath;
    }

    private String saveRepositoryAsArchive(DockerClient dockerClient, String imageId, String destinationPath)
            throws IOException {
        logger.println("Saving repo to archive");

        File destinationFile = new File(destinationPath);
        File destinationDir = destinationFile.getParentFile();
        logger.printf("Saving archive to %s", destinationFile);

        if (!destinationDir.exists() && !destinationDir.mkdirs()) {
            throw new IOException("Failed to create destination directory: " + destinationDir.getAbsolutePath());
        }

        try (OutputStream outputStream = new FileOutputStream(destinationFile)) {
            SaveImageCmd saveImageCmd = dockerClient.saveImageCmd(imageId);
            InputStream inputStream = saveImageCmd.exec();
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }

            logger.println("Repository saved as a tarball archive successfully.");
        }

        return destinationFile.getAbsolutePath();
    }
}
