package io.jenkins.plugins.amazoninspectorbuildstep.bomerman;

import hudson.model.Job;
import io.jenkins.plugins.amazoninspectorbuildstep.credentials.UsernameCredentialsHelper;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Map;

import static io.jenkins.plugins.amazoninspectorbuildstep.AmazonInspectorBuilder.logger;

public class BomermanRunner {
    private String dockerUsername;
    public String bomermanPath;
    public String archivePath;

    public BomermanRunner(String bomermanPath, String archivePath, String dockerUsername) {
        this.bomermanPath = bomermanPath;
        this.archivePath = archivePath;
        this.dockerUsername = dockerUsername;
    }

    public String run(Job<?, ?> job) throws IOException {
        return runBomerman(job, bomermanPath, archivePath);
    }

    private String runBomerman(Job<?, ?> job, String bomermanPath, String archivePath) throws IOException {
        String[] command = new String[] {
                bomermanPath, "container", "--image", archivePath
        };

        ProcessBuilder builder = new ProcessBuilder(command);
        Map<String, String> environment = builder.environment();
        environment.put("INSPECTOR_SBOMGEN_USERNAME", dockerUsername);
        environment.put("INSPECTOR_SBOMGEN_PASSWORD", new UsernameCredentialsHelper(job).getKeyFromStore(dockerUsername));

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

    private static String processBomermanOutput(String sbom) {
        sbom.replaceAll("time=.+file=.+\"", "");
        return sbom.substring(sbom.indexOf("{"), sbom.lastIndexOf("}") + 1);
    }
}
