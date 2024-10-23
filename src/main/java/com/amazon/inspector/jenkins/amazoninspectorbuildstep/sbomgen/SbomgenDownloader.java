package com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.FilePath;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.net.URL;
import java.util.concurrent.ExecutionException;

public class SbomgenDownloader {

    private static final String BASE_URL = "https://amazon-inspector-sbomgen.s3.amazonaws.com/latest/linux/%s/inspector-sbomgen.zip";

    public static String getBinary(String configInput, FilePath workspace) throws IOException, InterruptedException, ExecutionException {
        String url = getUrl(configInput);
        FilePath zipPath = downloadFile(url, workspace);
        return unzipFile(zipPath);
    }

    private static String getUrl(String configInput) {
        String osName = System.getProperty("os.name").toLowerCase();
        if (!osName.contains("linux")) {
            throw new UnsupportedOperationException("Unsupported OS: " + osName);
        }

        String architecture = "amd64";

        String osArch = System.getProperty("os.arch").toLowerCase();
        if (osArch.contains("arm64") || osArch.contains("aarch64")) {
            architecture = "arm64";
        } else if (!osArch.contains("amd64") && !osArch.contains("x86_64")) {
            throw new UnsupportedOperationException("Unsupported architecture: " + osArch);
        }

        if (configInput != null && !configInput.isEmpty()) {
            if (configInput.equalsIgnoreCase("linuxAmd64")) {
                architecture = "amd64";
            } else if (configInput.equalsIgnoreCase("linuxArm64")) {
                architecture = "arm64";
            } else {
                throw new IllegalArgumentException("Invalid configInput: " + configInput);
            }
        }
        return String.format(BASE_URL, architecture);
    }

    private static FilePath downloadFile(String url, FilePath workspace) throws IOException, InterruptedException {
        FilePath sbomgenZip = workspace.child("inspector-sbomgen.zip");
        sbomgenZip.copyFrom(new BufferedInputStream(new URL(url).openStream()));
        return sbomgenZip;
    }

    @SuppressFBWarnings
    private static String unzipFile(FilePath zip) throws IOException, InterruptedException {
        FilePath destination = zip.getParent();
        zip.unzip(destination);
        FilePath binaryPath = destination.child("inspector-sbomgen");
        binaryPath.chmod(0755);
        return binaryPath.getRemote();
    }
}
