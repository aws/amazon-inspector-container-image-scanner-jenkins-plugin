package com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.FilePath;
import hudson.remoting.VirtualChannel;
import org.jenkinsci.remoting.RoleChecker;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

@SuppressFBWarnings
class DownloaderCallable implements FilePath.FileCallable {
    String destinationPath;

    DownloaderCallable(String destinationPath) {
        this.destinationPath = destinationPath;
    }

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

    private static File newFile(File destinationDir, ZipEntry zipEntry) throws IOException {
        File destFile = new File(destinationDir, zipEntry.getName());

        String destDirPath = destinationDir.getCanonicalPath();
        String destFilePath = destFile.getCanonicalPath();

        if (!destFilePath.startsWith(destDirPath + File.separator)) {
            throw new IOException("Entry is outside of the target dir: " + zipEntry.getName());
        }

        return destFile;
    }
}
