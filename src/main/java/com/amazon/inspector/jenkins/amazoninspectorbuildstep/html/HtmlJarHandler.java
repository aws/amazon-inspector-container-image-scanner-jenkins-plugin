package com.amazon.inspector.jenkins.amazoninspectorbuildstep.html;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.AmazonInspectorBuilder;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.FilePath;
import lombok.AllArgsConstructor;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringEscapeUtils;

import java.io.IOException;
import java.io.InputStream;
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
                scriptStart + "\n\t\t\tconst txt = `" + trimmedJson + "`");
        return htmlContent;
    }

    @SuppressFBWarnings()
    public String readStringFromJarEntry(String fileName) throws IOException {
        JarFile jarFile = new JarFile(jarPath);
        JarEntry entry = jarFile.getJarEntry(fileName);
        InputStream inputStream = jarFile.getInputStream(entry);
        String content = IOUtils.toString(inputStream, StandardCharsets.UTF_8);
        inputStream.close();
        jarFile.close();
        return content;
    }
}
