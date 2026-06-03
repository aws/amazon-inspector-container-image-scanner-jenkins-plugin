package com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.AmazonInspectorBuilder;
import com.google.common.annotations.VisibleForTesting;
import hudson.FilePath;
import hudson.Launcher;
import lombok.Getter;

import java.io.File;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@SuppressWarnings("lgtm[jenkins/plaintext-storage]")
@Getter
public class SbomgenRunner {

    private final String sbomgenPath;
    private final String archiveType;
    private final String archivePath;
    private final Launcher launcher;
    private final FilePath workspace;
    private final String dockerUsername;
    private final String dockerPassword;
    private final String sbomgenSkipFiles;
    private final boolean isLicenseCollectionEnabled;

    public SbomgenRunner(Launcher launcher, FilePath workspace, String sbomgenPath, String activeArchiveType,
                         String archivePath, String dockerUsername, String dockerPassword,
                         String sbomgenSkipFiles, boolean isLicenseCollectionEnabled) {
        this.sbomgenPath = sbomgenPath;
        this.archivePath = archivePath;
        this.archiveType = activeArchiveType;
        this.dockerUsername = dockerUsername;
        this.dockerPassword = dockerPassword;
        this.launcher = launcher;
        this.workspace = workspace;
        this.sbomgenSkipFiles = sbomgenSkipFiles;
        this.isLicenseCollectionEnabled = isLicenseCollectionEnabled;
    }

    public String run() throws Exception {
        return runSbomgen(sbomgenPath, archivePath);
    }

    private String runSbomgen(String sbomgenPath, String archivePath) throws Exception {
        FilePath sbomgenFilePath;
        if (workspace.getChannel() != null) {
            sbomgenFilePath = new FilePath(workspace.getChannel(), sbomgenPath);
        } else {
            sbomgenFilePath = new FilePath(new File(sbomgenPath));
        }

        if (!isValidPath(sbomgenFilePath.getRemote())) {
            throw new IllegalArgumentException("Invalid sbomgen path: " + sbomgenPath);
        }

        Map<String, String> environment = new HashMap<>();
        if (dockerPassword != null && !dockerPassword.isEmpty()) {
            environment.put("INSPECTOR_SBOMGEN_USERNAME", dockerUsername);
            environment.put("INSPECTOR_SBOMGEN_PASSWORD", dockerPassword);
        }

        AmazonInspectorBuilder.getLogger().println("Making downloaded SBOMGen executable...");
        SbomgenUtils.runCommand(new String[]{"chmod", "+x", sbomgenFilePath.getRemote()},
                launcher, environment);

        AmazonInspectorBuilder.getLogger().println("Running command...");
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

        AmazonInspectorBuilder.getLogger().println(Arrays.toString(baseCommandList));

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

                AmazonInspectorBuilder.getLogger().println("DEBUG: --skip-files argument: " +
                        skipFilesJoined);
                AmazonInspectorBuilder.getLogger().println(Arrays.toString(baseCommandList));
            }
        }

        if (isLicenseCollectionEnabled) {
            String[] extendedCommandList = Arrays.copyOf(baseCommandList,
                    baseCommandList.length + 1);
            extendedCommandList[extendedCommandList.length - 1] = "--collect-licenses";
            baseCommandList = extendedCommandList;

            AmazonInspectorBuilder.getLogger().println("License collection enabled, adding --collect-licenses flag");
            AmazonInspectorBuilder.getLogger().println(Arrays.toString(baseCommandList));
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
