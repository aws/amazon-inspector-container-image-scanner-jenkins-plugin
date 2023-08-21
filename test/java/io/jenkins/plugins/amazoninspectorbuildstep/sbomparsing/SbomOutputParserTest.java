package io.jenkins.plugins.amazoninspectorbuildstep.sbomparsing;

import com.google.gson.Gson;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Components.Rating;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.SbomData;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.Assert.assertEquals;

public class SbomOutputParserTest {
    @Test
    public void testParseNullVulnSbom() throws IOException {
        // Convert file at path to text
        String sbom = readStringFromFile("test/data/SbomOutputExampleNullVuln.json");
        SbomData sbomData = new Gson().fromJson(sbom, SbomData.class);
        SbomOutputParser parser = new SbomOutputParser(sbomData);
        Map<Severity, Integer> results = parser.parseSbom().getCounts();

        assertEquals(Optional.ofNullable(results.get(Severity.CRITICAL)), Optional.of(0));
    }

    @Test
    public void testParseSbom() throws IOException {
        // Convert file at path to text
        String sbom = readStringFromFile("test/data/SbomOutputExample.json");
        SbomData sbomData = new Gson().fromJson(sbom, SbomData.class);
        SbomOutputParser parser = new SbomOutputParser(sbomData);
        Map<Severity, Integer> results = parser.parseSbom().getCounts();

        assertEquals(Optional.ofNullable(results.get(Severity.CRITICAL)), Optional.of(1));
    }

    @Test
    public void getHighestSeverityFromList() throws IOException {
        String sbom = readStringFromFile("test/data/SbomOutputExample.json");
        SbomData sbomData = new Gson().fromJson(sbom, SbomData.class);
        SbomOutputParser parser = new SbomOutputParser(sbomData);

        List<Rating> ratings = List.of(
                Rating.builder()
                        .severity("critical")
                        .build(),
                Rating.builder()
                        .severity("critical")
                        .build(),
                Rating.builder()
                        .severity("high")
                        .build(),
                Rating.builder()
                        .severity("low")
                        .build(),
                Rating.builder()
                        .severity("medium")
                        .build(),
                Rating.builder()
                        .severity("none")
                        .build()
        );


        Severity highestSeverity = parser.getHighestRatingFromList(ratings);
        assertEquals(highestSeverity, Severity.CRITICAL);
    }

    public static String readStringFromFile(String filePath) throws IOException {
        return Files.readString(Paths.get(filePath));
    }
}
