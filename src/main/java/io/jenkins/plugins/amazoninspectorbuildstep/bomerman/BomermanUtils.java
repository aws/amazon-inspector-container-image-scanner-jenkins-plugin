package io.jenkins.plugins.amazoninspectorbuildstep.bomerman;

public class BomermanUtils {

    public static String processBomermanOutput(String sbom) {
        sbom.replaceAll("time=.+file=.+\"", "");
        return sbom.substring(sbom.indexOf("{"), sbom.lastIndexOf("}") + 1);
    }
}
