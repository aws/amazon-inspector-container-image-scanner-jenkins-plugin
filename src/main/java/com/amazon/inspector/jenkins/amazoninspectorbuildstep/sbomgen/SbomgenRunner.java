package com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.AmazonInspectorBuilder;
import com.google.common.annotations.VisibleForTesting;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.exception.SbomgenNotFoundException;
import lombok.Setter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Map;

import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen.SbomgenUtils.processSbomgenOutput;
import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen.SbomgenUtils.stripProperties;

@SuppressWarnings("lgtm[jenkins/plaintext-storage]")
public class SbomgenRunner {
    public String sbomgenPath;
    public String archivePath;
    @Setter
    public static String dockerUsername;
    @Setter
    public String dockerPassword;

    public SbomgenRunner(String sbomgenPath, String archivePath, String dockerUsername) {
        this.sbomgenPath = sbomgenPath;
        this.archivePath = archivePath;
        this.dockerUsername = dockerUsername;
    }

    public SbomgenRunner(String sbomgenPath, String archivePath, String dockerUsername, String dockerPassword) {
        this.sbomgenPath = sbomgenPath;
        this.archivePath = archivePath;
        this.dockerUsername = dockerUsername;
        this.dockerPassword = dockerPassword;
    }

    public String run() throws Exception {
        return runSbomgen(sbomgenPath, archivePath);
    }

    private String runSbomgen(String sbomgenPath, String archivePath) throws Exception {
        if (!isValidPath(sbomgenPath)) {
            throw new IllegalArgumentException("Invalid sbomgen path: " + sbomgenPath);
        }

        if (!isValidPath(archivePath)) {
            throw new IllegalArgumentException("Invalid archive path: " + archivePath);
        }
        AmazonInspectorBuilder.logger.println("Making downloaded SBOMGen executable...");
        new ProcessBuilder(new String[]{"chmod", "+x", sbomgenPath}).start();

        AmazonInspectorBuilder.logger.println("Running command...");
        String[] command = new String[] {
                sbomgenPath, "container", "--image", archivePath
        };
        AmazonInspectorBuilder.logger.println(Arrays.toString(command));
        ProcessBuilder builder = new ProcessBuilder(command);
        Map<String, String> environment = builder.environment();

        if (dockerPassword != null && !dockerPassword.isEmpty()) {
            environment.put("INSPECTOR_SBOMGEN_USERNAME", dockerUsername);
            environment.put("INSPECTOR_SBOMGEN_PASSWORD", dockerPassword);
        }


        builder.redirectErrorStream(true);
        Process p = null;

        try {
            p = builder.start();
        } catch (IOException e) {
            throw new SbomgenNotFoundException(String.format("There was an issue running inspector-sbomgen, " +
                    "is %s the correct path?", sbomgenPath));
        }

        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        StringBuilder sb = new StringBuilder();
        while (true) {
            line = r.readLine();
            AmazonInspectorBuilder.logger.println(line);
            sb.append(line + "\n");
            if (line == null) { break; }
        }

        return stripProperties(processSbomgenOutput(sb.toString()));
    }

    @VisibleForTesting
    protected boolean isValidPath(String path) {
        String regex = "^[a-zA-Z0-9/._\\-:]+$";
        return path.matches(regex);
    }
}