package com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.AmazonInspectorBuilder;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.exception.SbomgenNotFoundException;
import com.google.common.annotations.VisibleForTesting;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.exception.MalformedScanOutputException;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Launcher;
import hudson.Proc;
import hudson.util.ArgumentListBuilder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Map;

public class SbomgenUtils {

    public static String processSbomgenOutput(String sbom) throws MalformedScanOutputException {
        int startIndex = sbom.indexOf("{");
        int endIndex = sbom.lastIndexOf("}");

        if (startIndex == -1 || endIndex == -1 || startIndex > endIndex) {
            throw new MalformedScanOutputException("Sbom scanning output formatted incorrectly.\nSbom Content:\n" + sbom);
        }

        return sbom.substring(startIndex, endIndex + 1);
    }

    @VisibleForTesting
    @SuppressFBWarnings()
    public static String stripProperties(String sbom) {
        JsonObject json = JsonParser.parseString(sbom).getAsJsonObject();

        if (json == null || json.get("components") == null) {
            AmazonInspectorBuilder.logger.println("Strip properties failed the null check.");
            return sbom;
        }

        JsonArray components = json.get("components").getAsJsonArray();

        for (JsonElement component : components) {
            component.getAsJsonObject().remove("properties");
        }

        return json.toString();
    }

    public static String runCommand(String[] commandList, Launcher launcher, Map<String, String> env) throws SbomgenNotFoundException, UnsupportedEncodingException {
        ArgumentListBuilder command = new ArgumentListBuilder();
        command.add(commandList);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Launcher.ProcStarter ps = launcher.new ProcStarter().stdout(baos).cmds(command);

        ps.envs(env);
        try {
            Proc proc = launcher.launch(ps);
            proc.join();
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }

        return new String(baos.toByteArray(), "UTF-8");
    }
}