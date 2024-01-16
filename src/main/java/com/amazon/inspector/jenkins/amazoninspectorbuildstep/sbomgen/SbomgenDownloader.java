package com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen;

import javax.management.openmbean.InvalidKeyException;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class SbomgenDownloader {

    public static String getBinary(String configInput) throws IOException {
        String url = getUrl(configInput);
        String zipPath = downloadFile(url);
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

    private static String downloadFile(String url) throws IOException {
        String tmpdir = Files.createTempDirectory("sbomgen").toFile().getAbsolutePath();
        String sbomgenPath = tmpdir + "/inspector_sbomgen.zip";

        try (BufferedInputStream in = new BufferedInputStream(new URL(url).openStream());
             FileOutputStream fileOutputStream = new FileOutputStream(sbomgenPath)) {
            byte dataBuffer[] = new byte[1024];
            int bytesRead;
            while ((bytesRead = in.read(dataBuffer, 0, 1024)) != -1) {
                fileOutputStream.write(dataBuffer, 0, bytesRead);
            }
        } catch (IOException e) {
            throw new IOException("There was an issue downloading the SBOMGen utility, please run the plugin by " +
                    "providing the utility manually.");
        }

        return sbomgenPath;
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


    private static String unzipFile(String zipPath) throws IOException {
        String destinationPath = zipPath.replace(".zip", "");
        byte[] buffer = new byte[1024];

        ZipInputStream zis = new ZipInputStream(new FileInputStream(zipPath));
        ZipEntry zipEntry = zis.getNextEntry();
        String sbomgenPath = "";
        while (zipEntry != null) {
            System.out.println(zipEntry.getName());
            File newFile = newFile(new File(destinationPath), zipEntry);
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
}
