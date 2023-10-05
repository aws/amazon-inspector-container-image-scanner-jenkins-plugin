package io.jenkins.plugins.amazoninspectorbuildstep.bomerman;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import static io.jenkins.plugins.amazoninspectorbuildstep.bomerman.BomermanConstants.BOMERMAN_NAME;

public class BomermanJarHandler {
    public String jarPath;

    public BomermanJarHandler(String jarPath) {
        this.jarPath = jarPath;
    }

    public static String getOperatingSystem() {
        return System.getProperty("os.name");
    }

    public static String getCpuArch() {
        return System.getProperty("os.arch");
    }

    public String copyBomermanToDir(String destDirPath) throws IOException, BomermanNotFoundException {
        File tempFile = new File(destDirPath, BOMERMAN_NAME);

        JarFile jarFile = new JarFile(jarPath);

        JarEntry entry = jarFile.getJarEntry(BomermanVersionManager.getBomermanName(getOperatingSystem(), getCpuArch()));
        try (InputStream inputStream = jarFile.getInputStream(entry);
             FileOutputStream outputStream = new FileOutputStream(tempFile)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }

        tempFile.setExecutable(true);

        return tempFile.getAbsolutePath();
    }
}
