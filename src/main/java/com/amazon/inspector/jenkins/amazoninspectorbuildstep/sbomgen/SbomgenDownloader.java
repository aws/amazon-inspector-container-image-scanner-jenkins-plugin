package com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.FilePath;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.net.URL;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.AmazonInspectorBuilder.logger;

public class SbomgenDownloader {
    private static final String BASE_URL = "https://amazon-inspector-" +
            "sbomgen.s3.amazonaws.com/latest/linux/%s/inspector-sbomgen.zip";
    public static String getBinary(FilePath workspace, hudson.EnvVars env, hudson.Launcher launcher) throws IOException, InterruptedException, ExecutionException {
        String url = getUrl(workspace, env, launcher);
        FilePath zipPath = downloadFile(url, workspace);
        return unzipFile(zipPath);
    }

    public static String getUrl(FilePath workspace, hudson.EnvVars env, hudson.Launcher launcher) throws IOException, InterruptedException {
        String osName = System.getProperty("os.name").toLowerCase();
        logger.println("Detected OS Name: " + osName);
        if (!osName.contains("linux")) {
            throw new UnsupportedOperationException("Unsupported OS: " + osName);
        }

        String architecture = "amd64";
        String osArch = null;
        
        // Try to get architecture from agent using launcher (same pattern as SbomgenRunner)
        if (launcher != null) {
            try {
                java.util.Map<String, String> environment = new java.util.HashMap<>();
                String output = SbomgenUtils.runCommand(new String[]{"uname", "-m"}, launcher, environment);
                if (output != null && !output.trim().isEmpty()) {
                    osArch = output.trim();
                    logger.println("Detected OS Architecture (from agent): " + osArch);
                }
            } catch (Exception e) {
                logger.println("Failed to detect architecture from agent: " + e.getMessage());
            }
        }
        
        // Fallback to System.getProperty if agent detection failed
        if (osArch == null || osArch.trim().isEmpty()) {
            osArch = System.getProperty("os.arch").toLowerCase();
            logger.println("Detected OS Architecture (fallback from master): " + osArch);
        }
        
        osArch = osArch.toLowerCase().trim();
        if (osArch.contains("arm64") || osArch.contains("aarch64")) {
            architecture = "arm64";
        } else if (!osArch.contains("amd64") && !osArch.contains("x86_64")) {
            throw new UnsupportedOperationException("Unsupported architecture: " + osArch);
        }
        return String.format(BASE_URL, architecture);
    }

    private static FilePath downloadFile(String url, FilePath workspace) throws IOException, InterruptedException {
        FilePath sbomgenZip = workspace.child("inspector-sbomgen.zip");
        sbomgenZip.copyFrom(new BufferedInputStream(new URL(url).openStream()));
        return sbomgenZip;
    }

    @SuppressFBWarnings()
    private static String unzipFile(FilePath zip) throws IOException, InterruptedException, ExecutionException {
        FilePath destination = zip.getParent().child(zip.getRemote().replace(".zip", ""));
        Future<String> callable = zip.actAsync(new DownloaderCallable(destination.getRemote()));
        return callable.get();
    }
}
