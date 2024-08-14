package com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.AmazonInspectorBuilder;
import com.google.common.annotations.VisibleForTesting;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.exception.SbomgenNotFoundException;
import hudson.FilePath;
import hudson.Launcher;
import hudson.Proc;
import hudson.util.ArgumentListBuilder;
import lombok.Setter;
import org.apache.commons.io.IOUtils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen.SbomgenUtils.processSbomgenOutput;

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

    public SbomgenRunner(Launcher launcher, String sbomgenPath, String archivePath, String dockerUsername) {
        this.sbomgenPath = sbomgenPath;
        this.archivePath = archivePath;
        this.dockerUsername = dockerUsername;
        this.launcher = launcher;
    }

    public SbomgenRunner(Launcher launcher, String sbomgenPath, String archivePath, String dockerUsername, String dockerPassword) {
        this.sbomgenPath = sbomgenPath;
        this.archivePath = archivePath;
        this.dockerUsername = dockerUsername;
        this.dockerPassword = dockerPassword;
        this.launcher = launcher;
    }

    public SbomgenRunner(Launcher launcher, String sbomgenPath, String activeArchiveType, String archivePath, String dockerUsername, String dockerPassword) {
        this.sbomgenPath = sbomgenPath;
        this.archivePath = archivePath;
        this.archiveType = activeArchiveType;
        this.dockerUsername = dockerUsername;
        this.dockerPassword = dockerPassword;
        this.launcher = launcher;
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
        SbomgenUtils.runCommand(new String[]{"chmod", "+x", sbomgenFilePath.getRemote()}, launcher, environment);

        AmazonInspectorBuilder.logger.println("Running command...");
        String option = "--image";
        if (!archiveType.equals("container")) {
            option = "--path";
        }
        String[] commandList = new String[] {
                sbomgenFilePath.getRemote(), archiveType, option, archivePath
        };
        AmazonInspectorBuilder.logger.println(Arrays.toString(commandList));
        String output = SbomgenUtils.runCommand(commandList, launcher, environment);

        return SbomgenUtils.processSbomgenOutput(output);
    }

    @VisibleForTesting
    protected boolean isValidPath(String path) {
        String regex = "^[a-zA-Z0-9/._\\-:]+$";
        return path.matches(regex);
    }
}