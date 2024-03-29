package com.amazon.inspector.jenkins.amazoninspectorbuildstep.html;

import hudson.FilePath;
import lombok.AllArgsConstructor;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringEscapeUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

@AllArgsConstructor
public class HtmlJarHandler {
    public String jarPath;
    public String htmlData;

    public FilePath copyHtmlToDir(FilePath workspace, String buildId) throws IOException, InterruptedException {
        String htmlFileName = "index.html";
        String htmlStr = readStringFromJarEntry(htmlFileName);
        String injectedHtmlStr = injectHtmlData(htmlStr);
        FilePath htmlFile = workspace.child(String.format("%s/%s", buildId, htmlFileName));
        htmlFile.write(injectedHtmlStr, "UTF-8");
        return htmlFile;
    }

    public String injectHtmlData(String htmlContent) throws IOException {
        String scriptStart = "<script type=\"text/javascript\">";
        String trimmedJson = StringEscapeUtils.unescapeJava(htmlData).replace("\n", "")
                .replace("\t", "");
        htmlContent = htmlContent.replaceAll(scriptStart,
                scriptStart + "\n\t\t\tconst txt = '" + trimmedJson + "'");

        return htmlContent;
    }

    public String readStringFromJarEntry(String fileName) throws IOException {
        JarFile jarFile = new JarFile(jarPath);
        JarEntry entry = jarFile.getJarEntry(fileName);
        return IOUtils.toString(jarFile.getInputStream(entry), StandardCharsets.UTF_8);
    }
}
