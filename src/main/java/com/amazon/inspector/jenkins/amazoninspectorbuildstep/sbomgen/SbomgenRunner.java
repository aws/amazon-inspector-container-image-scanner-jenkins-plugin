package com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.AmazonInspectorBuilder;
import com.google.common.annotations.VisibleForTesting;
import hudson.FilePath;
import hudson.Launcher;
import lombok.Setter;

import java.io.File;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@SuppressWarnings("lgtm[jenkins/plaintext-storage]")
public class SbomgenRunner {

    public String sbomgenPath;
    public String archiveType;
    public String archivePath;
    public Launcher launcher;

    @Setter
    public String dockerUsername;

    @Setter
    public String dockerPassword;

    private final String sbomgenSkipFiles;

    public SbomgenRunner(Launcher launcher, String sbomgenPath, String activeArchiveType,
                         String archivePath, String dockerUsername, String dockerPassword,
                         String sbomgenSkipFiles) {
        this.sbomgenPath = sbomgenPath;
        this.archivePath = archivePath;
        this.archiveType = activeArchiveType;
        this.dockerUsername = dockerUsername;
        this.dockerPassword = dockerPassword;
        this.launcher = launcher;
        this.sbomgenSkipFiles = sbomgenSkipFiles;
    }

    public String run() throws Exception {
        return runSbomgen(sbomgenPath, archivePath);
    }

    private String runSbomgen(String sbomgenPath, String archivePath) throws Exception {
        FilePath sbomgenFilePath = new FilePath(new File(sbomgenPath));

        if (!isValidPath(sbomgenFilePath.getRemote())) {
            throw new IllegalArgumentException("Invalid sbomgen path: " + sbomgenPath);
        }

        Map<String, String> environment = new HashMap<>();
        if (dockerPassword != null && !dockerPassword.isEmpty()) {
            environment.put("INSPECTOR_SBOMGEN_USERNAME", dockerUsername);
            environment.put("INSPECTOR_SBOMGEN_PASSWORD", dockerPassword);
        }

        AmazonInspectorBuilder.logger.println("Making downloaded SBOMGen executable...");
        SbomgenUtils.runCommand(new String[]{"chmod", "+x", sbomgenFilePath.getRemote()},
                launcher, environment);

        AmazonInspectorBuilder.logger.println("Running command...");
        String option = "--image";
        if (!archiveType.equals("container")) {
            option = "--path";
        }

        String[] baseCommandList = new String[] {
                sbomgenFilePath.getRemote(),
                archiveType,
                option,
                archivePath
        };

        AmazonInspectorBuilder.logger.println(Arrays.toString(baseCommandList));

        if (sbomgenSkipFiles != null && !sbomgenSkipFiles.trim().isEmpty()) {
            String[] patterns = sbomgenSkipFiles.split("\\r?\\n");
            List<String> validPatterns = Arrays.stream(patterns)
                    .map(String::trim)
                    .filter(p -> !p.isEmpty())
                    .collect(Collectors.toList());

            if (!validPatterns.isEmpty()) {
                String skipFilesJoined = String.join(",", validPatterns);
                String[] extendedCommandList = Arrays.copyOf(baseCommandList,
                        baseCommandList.length + 2);
                extendedCommandList[extendedCommandList.length - 2] = "--skip-files";
                extendedCommandList[extendedCommandList.length - 1] = skipFilesJoined;
                baseCommandList = extendedCommandList;

                AmazonInspectorBuilder.logger.println("DEBUG: --skip-files argument: " +
                        skipFilesJoined);
                AmazonInspectorBuilder.logger.println(Arrays.toString(baseCommandList));
            }
        }

        String output = SbomgenUtils.runCommand(baseCommandList, launcher, environment);
        return SbomgenUtils.processSbomgenOutput(output);
    }

    @VisibleForTesting
    protected boolean isValidPath(String path) {
        // Validates paths for container images and file paths while preventing command injection
        // Allows: alphanumeric, forward slashes, dots, underscores, hyphens, colons, and spaces
        // Blocks: shell metacharacters like &&, ;, |, $(), backticks, @ to prevent injection attacks
        String regex = "^[a-zA-Z0-9/._\\-: ]+$";
        return path.matches(regex);
    }
}
