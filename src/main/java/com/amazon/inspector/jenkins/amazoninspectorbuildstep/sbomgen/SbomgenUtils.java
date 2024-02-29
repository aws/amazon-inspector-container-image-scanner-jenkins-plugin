package com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.AmazonInspectorBuilder;
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

        if (json == null || json.getAsJsonObject() == null || json.getAsJsonObject().get("components") == null) {
            AmazonInspectorBuilder.logger.printf("Strip properties failed the null check. json: %s, jsonObject: %s, " +
                    "components: %s\n", json == null, json.getAsJsonObject() == null,
                    json.getAsJsonObject().get("components") == null);
            return sbom;
        }

        JsonArray components = json.getAsJsonObject().get("components").getAsJsonArray();

        for (JsonElement component : components) {
            component.getAsJsonObject().remove("properties");
        }

        return json.toString();
    }
}
