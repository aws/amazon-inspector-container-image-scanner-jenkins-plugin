package io.jenkins.plugins.awsinspectorbuildstep.dockerutils;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.List;

public class EcrImagePuller {
    String imageUri;

    public EcrImagePuller(String imageUri) {
        this.imageUri = imageUri;
    }

    public static void main(String[] args) {
        EcrImagePuller imagePuller = new EcrImagePuller("414879708742.dkr.ecr.us-east-1.amazonaws.com/test:latest");
        imagePuller.pullDockerImage("us-east-1");
        new DockerRepositoryArchiver("414879708742.dkr.ecr.us-east-1.amazonaws.com/test:latest", System.out)
                .archiveRepo(new File("/Users/waltwilo/workplace/EeveeCICDPlugin/src/EeveeCICDJenkinsPlugin/workspace/archives/testimage2.tar"));
    }

    public void pullDockerImage(String region) {
        String[] ecrCommand = {
                "aws",
                "ecr",
                "get-login-password",
                "--region",
                region
        };

        String[] dockerCommand = {
                "docker",
                "login",
                "--username",
                "AWS",
                "--password-stdin",
                imageUri
        };

        String[] dockerPullCommand = {
                "docker",
                "image",
                "pull",
                imageUri,
        };

        try {

            List<Process> processes = ProcessBuilder.startPipeline(
                    List.of(
                            new ProcessBuilder(ecrCommand).inheritIO().redirectOutput(ProcessBuilder.Redirect.PIPE),
                            new ProcessBuilder(dockerCommand).redirectError(ProcessBuilder.Redirect.INHERIT),
                            new ProcessBuilder(dockerPullCommand)
                    )
            );

            for (Process process : processes) {

                InputStream inputStream = process.getInputStream();
                InputStream errorStream = process.getErrorStream();
                BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));

                String line;
                while ((line = reader.readLine()) != null) {
                    System.out.println("line");
                    System.out.println(line);
                }

                reader = new BufferedReader(new InputStreamReader(errorStream));
                while ((line = reader.readLine()) != null) {
                    System.out.println("line");
                    System.out.println(line);
                }
                process.waitFor();
            }

        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}
