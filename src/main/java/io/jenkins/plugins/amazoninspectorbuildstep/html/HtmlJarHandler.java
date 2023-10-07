package io.jenkins.plugins.amazoninspectorbuildstep.html;

import io.jenkins.plugins.amazoninspectorbuildstep.exception.BomermanNotFoundException;
import lombok.AllArgsConstructor;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

@AllArgsConstructor
public class HtmlJarHandler {
    public String jarPath;

    public String copyHtmlToDir(String destDirPath) throws IOException {
        String logoFileName = "inspector-classic.png";
        String htmlFileName = "index.html";
        File tempLogoFile = new File(destDirPath, logoFileName);
        File tempHtmlFile = new File(destDirPath, htmlFileName);
        tempHtmlFile.setExecutable(true);

        copyFile(tempLogoFile, logoFileName);
        tempHtmlFile = copyFile(tempHtmlFile, htmlFileName);
        tempHtmlFile.setExecutable(true);

        return tempHtmlFile.getAbsolutePath();
    }

    public File copyFile(File destFile, String fileName) throws IOException {
        JarFile jarFile = new JarFile(jarPath);

        JarEntry entry = jarFile.getJarEntry(fileName);
        try (InputStream inputStream = jarFile.getInputStream(entry);
             FileOutputStream outputStream = new FileOutputStream(destFile)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }

        return destFile;
    }


}
