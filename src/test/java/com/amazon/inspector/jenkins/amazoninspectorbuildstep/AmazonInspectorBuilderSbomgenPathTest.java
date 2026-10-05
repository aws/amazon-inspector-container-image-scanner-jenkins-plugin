package com.amazon.inspector.jenkins.amazoninspectorbuildstep;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AmazonInspectorBuilderSbomgenPathTest {

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void testValidateManualSbomgenPathAcceptsAllowedPath(@TempDir Path temp) throws IOException {
        File sbomgen = createExecutable(temp.resolve("inspector-sbomgen"));

        assertDoesNotThrow(() -> AmazonInspectorBuilder.validateManualSbomgenPath(sbomgen.getAbsolutePath()));
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void testValidateManualSbomgenPathRejectsAtSign(@TempDir Path temp) throws IOException {
        File directory = temp.resolve("job@2").toFile();
        assertTrue(directory.mkdirs());
        File sbomgen = createExecutable(directory.toPath().resolve("inspector-sbomgen"));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> AmazonInspectorBuilder.validateManualSbomgenPath(sbomgen.getAbsolutePath()));
        assertEquals("Invalid sbomgen path: " + sbomgen.getAbsolutePath(), e.getMessage());
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void testValidateManualSbomgenPathRejectsShellMetacharacters(@TempDir Path temp) throws IOException {
        for (String name : new String[] {"sbomgen;id", "sbomgen$(id)", "sbomgen`id`", "sbomgen|id", "sbomgen&&id"}) {
            File sbomgen = createExecutable(temp.resolve(name));

            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> AmazonInspectorBuilder.validateManualSbomgenPath(sbomgen.getAbsolutePath()));
            assertEquals("Invalid sbomgen path: " + sbomgen.getAbsolutePath(), e.getMessage());
        }
    }

    @Test
    void testValidateManualSbomgenPathRejectsMissingFile(@TempDir Path temp) {
        String missing = temp.resolve("inspector-sbomgen").toString();

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> AmazonInspectorBuilder.validateManualSbomgenPath(missing));
        assertEquals("Provided SBOMgen path is invalid or not executable: " + missing, e.getMessage());
    }

    @Test
    void testValidateManualSbomgenPathRejectsEmptyPath() {
        assertThrows(IllegalArgumentException.class, () -> AmazonInspectorBuilder.validateManualSbomgenPath(null));
        assertThrows(IllegalArgumentException.class, () -> AmazonInspectorBuilder.validateManualSbomgenPath(""));
    }

    private static File createExecutable(Path path) throws IOException {
        File file = Files.createFile(path).toFile();
        assertTrue(file.setExecutable(true));
        return file;
    }
}
