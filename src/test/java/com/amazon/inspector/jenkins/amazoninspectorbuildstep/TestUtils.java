package com.amazon.inspector.jenkins.amazoninspectorbuildstep;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Sbom;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.SbomData;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class TestUtils {
    public static String readStringFromFile(String filePath) throws IOException {
        return new String(Files.readAllBytes(Paths.get(filePath)), StandardCharsets.UTF_8);
    }

    public static SbomData getSbomDataFromString(String rawSbom) {
        Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
        return SbomData.builder().sbom(gson.fromJson(rawSbom, Sbom.class)).build();
    }
}
