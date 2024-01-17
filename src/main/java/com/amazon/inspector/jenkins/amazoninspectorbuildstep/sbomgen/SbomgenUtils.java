package com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen;

import com.google.common.annotations.VisibleForTesting;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.exception.MalformedScanOutputException;

public class SbomgenUtils {

    public static String processSbomgenOutput(String sbom) throws MalformedScanOutputException {
        sbom.replaceAll("time=.+file=.+\"", "");
        int startIndex = sbom.indexOf("{");
        int endIndex = sbom.lastIndexOf("}");

        if (startIndex == -1 || endIndex == -1 || startIndex > endIndex) {
            throw new MalformedScanOutputException("Sbom scanning output formatted incorrectly.\nSbom Content:\n" + sbom);
        }

        return sbom.substring(startIndex, endIndex + 1);
    }

    @VisibleForTesting
    public static String stripProperties(String sbom) {
        JsonObject json = JsonParser.parseString(sbom).getAsJsonObject();
        JsonArray components = json.getAsJsonObject().get("components").getAsJsonArray();

        for (JsonElement component : components) {
            component.getAsJsonObject().remove("properties");
        }

        return json.toString();
    }
}
