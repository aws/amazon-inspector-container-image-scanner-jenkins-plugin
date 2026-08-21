package com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DownloaderCallableTest {

    private static final String SBOMGEN_ENTRY = "inspector-sbomgen-1.0.0/linux/amd64/inspector-sbomgen";

    @Test
    void invoke_returnsPathOfExtractedSbomgen(@TempDir Path temp) throws IOException {
        File zip = writeZip(temp.resolve("sbomgen.zip").toFile(), SBOMGEN_ENTRY);
        File destination = temp.resolve("out").toFile();

        String sbomgenPath = new DownloaderCallable(destination.getAbsolutePath()).invoke(zip, null);

        File extracted = new File(destination, SBOMGEN_ENTRY);
        assertEquals(extracted.getAbsolutePath(), sbomgenPath);
        assertTrue(extracted.isFile());
    }

    @Test
    @DisabledOnOs(OS.WINDOWS)
    void invoke_marksExtractedSbomgenExecutable(@TempDir Path temp) throws IOException {
        File zip = writeZip(temp.resolve("sbomgen.zip").toFile(), SBOMGEN_ENTRY);
        File destination = temp.resolve("out").toFile();

        new DownloaderCallable(destination.getAbsolutePath()).invoke(zip, null);

        assertTrue(new File(destination, SBOMGEN_ENTRY).canExecute());
    }

    @Test
    void invoke_returnsEmptyPathWhenArchiveHasNoSbomgenEntry(@TempDir Path temp) throws IOException {
        File zip = writeZip(temp.resolve("other.zip").toFile(), "inspector-sbomgen-1.0.0/README.md");
        File destination = temp.resolve("out").toFile();

        assertEquals("", new DownloaderCallable(destination.getAbsolutePath()).invoke(zip, null));
    }

    @Test
    void invoke_rejectsEntryEscapingDestinationDirectory(@TempDir Path temp) throws IOException {
        File zip = writeZip(temp.resolve("traversal.zip").toFile(), "../escaped.txt");
        File destination = temp.resolve("out").toFile();

        IOException exception = assertThrows(IOException.class,
                () -> new DownloaderCallable(destination.getAbsolutePath()).invoke(zip, null));

        assertTrue(exception.getMessage().contains("outside of the target dir"));
        assertFalse(temp.resolve("escaped.txt").toFile().exists());
    }

    @Test
    void invoke_rejectsNestedEntryEscapingDestinationDirectory(@TempDir Path temp) throws IOException {
        File zip = writeZip(temp.resolve("nested.zip").toFile(), "linux/../../escaped.txt");
        File destination = temp.resolve("out").toFile();

        IOException exception = assertThrows(IOException.class,
                () -> new DownloaderCallable(destination.getAbsolutePath()).invoke(zip, null));

        assertTrue(exception.getMessage().contains("outside of the target dir"));
        assertFalse(temp.resolve("escaped.txt").toFile().exists());
    }

    private static File writeZip(File zip, String entryName) throws IOException {
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(zip))) {
            zos.putNextEntry(new ZipEntry(entryName));
            zos.write("payload".getBytes(StandardCharsets.UTF_8));
            zos.closeEntry();
        }
        return zip;
    }
}
