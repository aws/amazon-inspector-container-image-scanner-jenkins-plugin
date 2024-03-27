package com.amazon.inspector.jenkins.amazoninspectorbuildstep.html;

import hudson.FilePath;
import lombok.AllArgsConstructor;
import org.apache.commons.lang3.StringEscapeUtils;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

@AllArgsConstructor
public class HtmlGenerator {
    private FilePath tempHtmlFile;

    public String generateNewHtml(String json) throws IOException {
        String htmlContent = getHtmlAsString();

        String scriptStart = "<script type=\"text/javascript\">";
        String trimmedJson = StringEscapeUtils.unescapeJava(json).replace("\n", "")
                .replace("\t", "");
        htmlContent = htmlContent.replaceAll(scriptStart,
                scriptStart + "\n\t\t\tconst txt = '" + trimmedJson + "'");

        return htmlContent;
    }

    private String getHtmlAsString()  throws IOException {
        File file = new File(tempHtmlFile.getRemote());
        byte[] encoded = Files.readAllBytes(Paths.get(tempHtmlFile.getRemote()));
        file.delete();
        return new String(encoded, StandardCharsets.UTF_8);
    }

    private void createFile(String htmlContent) {
        try {
            File file = new File(tempHtmlFile.getRemote());
            file.createNewFile();
            FileWriter fw = new FileWriter(file.getAbsoluteFile());
            BufferedWriter bw = new BufferedWriter(fw);
            bw.write(htmlContent);
            bw.close();
        } catch(IOException e) {
            e.printStackTrace();
        }
    }
}
