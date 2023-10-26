package io.jenkins.plugins.amazoninspectorbuildstep.bomerman;

import hudson.model.Job;
import io.jenkins.plugins.amazoninspectorbuildstep.credentials.UsernameCredentialsHelper;
import io.jenkins.plugins.amazoninspectorbuildstep.exception.MalformedScanOutputException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Map;

public class BomermanRunner {
    private String dockerUsername;
    public String bomermanPath;
    public String archivePath;

    public BomermanRunner(String bomermanPath, String archivePath, String dockerUsername) {
        this.bomermanPath = bomermanPath;
        this.archivePath = archivePath;
        this.dockerUsername = dockerUsername;
    }

    public String run(Job<?, ?> job) throws IOException, MalformedScanOutputException {
        return runBomerman(job, bomermanPath, archivePath);
    }

    private String runBomerman(Job<?, ?> job, String bomermanPath, String archivePath) throws IOException, MalformedScanOutputException {
        String[] command = new String[] {
                bomermanPath, "container", "--image", archivePath
        };

        ProcessBuilder builder = new ProcessBuilder(command);
        String dockerPassword = new UsernameCredentialsHelper(job).getKeyFromStore(dockerUsername);
        Map<String, String> environment = builder.environment();
        if (dockerPassword != null && !dockerPassword.isEmpty()) {
            environment.put("INSPECTOR_SBOMGEN_USERNAME", dockerUsername);
            environment.put("INSPECTOR_SBOMGEN_PASSWORD", dockerPassword);
        }

        builder.redirectErrorStream(true);
        Process p = builder.start();
        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        StringBuilder sb = new StringBuilder();
        while (true) {
            line = r.readLine();
            sb.append(line + "\n");
            if (line == null) { break; }
        }

        String output = sb.toString();
        return processBomermanOutput(output);
    }

    private static String processBomermanOutput(String sbom) throws MalformedScanOutputException {
        sbom.replaceAll("time=.+file=.+\"", "");
        int startIndex = sbom.indexOf("{");
        int endIndex = sbom.lastIndexOf("}");

        if (startIndex == -1 || endIndex == -1 || startIndex > endIndex) {
            throw new MalformedScanOutputException("Sbom scanning output formatted incorrectly.");
        }

        return sbom.substring(startIndex, endIndex + 1);
    }
}
