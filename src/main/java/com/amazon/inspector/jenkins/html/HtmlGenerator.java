package com.amazon.inspector.jenkins.html;

import lombok.AllArgsConstructor;
import org.apache.commons.lang.StringEscapeUtils;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

@AllArgsConstructor
public class HtmlGenerator {
    private String htmlPath;

    public void generateNewHtml(String json) throws IOException {
        String htmlContent = getHtmlAsString();

        String scriptStart = "<script type=\"text/javascript\">";
        String trimmedJson = StringEscapeUtils.unescapeJava(json).replace("\n", "")
                .replace("\t", "");
        htmlContent = htmlContent.replaceAll(scriptStart,
                scriptStart + "\n\t\t\tconst txt = '" + trimmedJson + "'");

        createFile(htmlContent);
    }

    private String getHtmlAsString()  throws IOException {
        File file = new File(htmlPath);
        byte[] encoded = Files.readAllBytes(Paths.get(htmlPath));
        file.delete();
        return new String(encoded, StandardCharsets.UTF_8);
    }

    private void createFile(String htmlContent) {
        try {
            File file = new File(htmlPath);
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
