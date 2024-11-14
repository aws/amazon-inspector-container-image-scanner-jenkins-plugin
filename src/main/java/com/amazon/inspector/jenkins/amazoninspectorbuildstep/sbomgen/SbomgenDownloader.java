package com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.FilePath;

import javax.management.openmbean.InvalidKeyException;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.net.URL;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

public class SbomgenDownloader {
    public static String getBinary(String configInput, FilePath workspace) throws IOException, InterruptedException, ExecutionException {
        String url = getUrl(configInput);
        FilePath zipPath = downloadFile(url, workspace);
        return unzipFile(zipPath);
    }

    private static String getUrl(String configInput) {
        final String linuxAmd64Url = "https://amazon-inspector-sbomgen.s3.amazonaws.com/latest/linux/amd64/inspector-sbomgen.zip";
        final String linuxArm64Url = "https://amazon-inspector-sbomgen.s3.amazonaws.com/latest/linux/arm64/inspector-sbomgen.zip";

        switch (configInput) {
            case "linuxAmd64":
                return linuxAmd64Url;
            case "linuxArm64":
                return linuxArm64Url;
        }
        if ("linuxAmd64Url".equals(configInput)) {
            return linuxAmd64Url;
        }
        if ("linuxArm64Url".equals(configInput)) {
            return linuxArm64Url;
        }


        throw new InvalidKeyException("No url corresponding to " + configInput);
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