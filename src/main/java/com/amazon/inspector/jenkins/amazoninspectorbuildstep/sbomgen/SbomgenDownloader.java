package com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.AmazonInspectorBuilder;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.FilePath;
import hudson.remoting.VirtualChannel;
import org.jenkinsci.remoting.RoleChecker;

import javax.management.openmbean.InvalidKeyException;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

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

    private static File newFile(File destinationDir, ZipEntry zipEntry) throws IOException {
        File destFile = new File(destinationDir, zipEntry.getName());

        String destDirPath = destinationDir.getCanonicalPath();
        String destFilePath = destFile.getCanonicalPath();

        if (!destFilePath.startsWith(destDirPath + File.separator)) {
            throw new IOException("Entry is outside of the target dir: " + zipEntry.getName());
        }

        return destFile;
    }


    @SuppressFBWarnings()
    private static String unzipFile(FilePath zip) throws IOException, InterruptedException, ExecutionException {
        FilePath destination = zip.getParent().child(zip.getRemote().replace(".zip", ""));
        Future<String> callable = zip.actAsync(new FilePath.FileCallable<String>() {
            @Override
            public void checkRoles(RoleChecker checker) throws SecurityException {

            }

            @Override
            public String invoke(File f, VirtualChannel channel) throws IOException {
                byte[] buffer = new byte[1024];
                ZipInputStream zis = new ZipInputStream(new FileInputStream(f));
                ZipEntry zipEntry = zis.getNextEntry();
                String sbomgenPath = "";
                while (zipEntry != null) {
                    File newFile = newFile(new File(destination.getRemote()), zipEntry);
                    if (zipEntry.getName().endsWith("inspector-sbomgen")) {
                        sbomgenPath = newFile.getAbsolutePath();
                        newFile.setExecutable(true);
                    }

                    if (zipEntry.isDirectory()) {
                        if (!newFile.isDirectory() && !newFile.mkdirs()) {
                            throw new IOException("Failed to create directory " + newFile);
                        }
                    } else {
                        File parent = newFile.getParentFile();
                        if (!parent.isDirectory() && !parent.mkdirs()) {
                            throw new IOException("Failed to create directory " + parent);
                        }

                        FileOutputStream fos = new FileOutputStream(newFile);
                        int len;
                        while ((len = zis.read(buffer)) > 0) {
                            fos.write(buffer, 0, len);
                        }
                        fos.close();
                    }
                    zipEntry = zis.getNextEntry();
                }

                zis.closeEntry();
                zis.close();


                return sbomgenPath;
            }
        });

        return callable.get();
    }
}