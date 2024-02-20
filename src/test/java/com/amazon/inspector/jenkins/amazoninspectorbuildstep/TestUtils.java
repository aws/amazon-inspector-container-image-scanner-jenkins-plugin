package com.amazon.inspector.jenkins.amazoninspectorbuildstep;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class TestUtils {
    public static String readStringFromFile(String filePath) throws IOException {
        return Files.readString(Paths.get(filePath));
    }
}
