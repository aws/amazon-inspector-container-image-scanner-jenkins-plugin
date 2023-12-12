package com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen;

import com.google.common.annotations.VisibleForTesting;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.exception.SbomgenNotFoundException;
import lombok.Setter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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
        return runSbomgen(sbomgenPath, archivePath, null);
    }

    public String runScan(String roleArn) throws Exception {
        return runSbomgen(sbomgenPath, archivePath, roleArn);
    }

    private String runSbomgen(String sbomgenPath, String archivePath, String roleArn) throws Exception {
        if (!isValidPath(sbomgenPath)) {
            throw new IllegalArgumentException("Invalid sbomgen path: " + sbomgenPath);
        }

        if (!isValidPath(archivePath)) {
            throw new IllegalArgumentException("Invalid archive path: " + archivePath);
        }

        List<String> command = new ArrayList<>();
        command.addAll(Arrays.asList(sbomgenPath, "container", "--image", archivePath));

        if (roleArn != null) {
            command.addAll(Arrays.asList("--scan-sbom", "--aws-iam-role-arn", roleArn));
        }

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
            sb.append(line + "\n");
            if (line == null) { break; }
        }

        String processedOutput = processSbomgenOutput(sb.toString());

        if (roleArn != null) {
            return processedOutput;
        }

        return stripProperties(processedOutput);
    }

    @VisibleForTesting
    protected boolean isValidPath(String path) {
        String regex = "^[a-zA-Z0-9/._\\-:]+$";
        return path.matches(regex);
    }
}