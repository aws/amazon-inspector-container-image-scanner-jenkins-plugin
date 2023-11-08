package io.jenkins.plugins.amazoninspectorbuildstep.bomerman;

import io.jenkins.plugins.amazoninspectorbuildstep.exception.BomermanNotFoundException;
import io.jenkins.plugins.amazoninspectorbuildstep.exception.MalformedScanOutputException;
import lombok.Setter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Map;

import static io.jenkins.plugins.amazoninspectorbuildstep.bomerman.BomermanUtils.processBomermanOutput;
import static io.jenkins.plugins.amazoninspectorbuildstep.bomerman.BomermanUtils.stripProperties;

public class BomermanRunner {
    public String bomermanPath;
    public String archivePath;
    @Setter
    public static String dockerUsername;
    @Setter
    public String dockerPassword;

    public BomermanRunner(String bomermanPath, String archivePath, String dockerUsername) {
        this.bomermanPath = bomermanPath;
        this.archivePath = archivePath;
        this.dockerUsername = dockerUsername;
    }

    public BomermanRunner(String bomermanPath, String archivePath, String dockerUsername, String dockerPassword) {
        this.bomermanPath = bomermanPath;
        this.archivePath = archivePath;
        this.dockerUsername = dockerUsername;
        this.dockerPassword = dockerPassword;
    }

    public String run() throws Exception {
        return runBomerman(bomermanPath, archivePath);
    }

    private String runBomerman(String bomermanPath, String archivePath) throws Exception {
        String[] command = new String[] {
                bomermanPath, "container", "--image", archivePath
        };

        ProcessBuilder builder = new ProcessBuilder(command);
        Map<String, String> environment = builder.environment();
        if (dockerPassword != null && !dockerPassword.isEmpty()) {
            environment.put("INSPECTOR_SBOMGEN_USERNAME", dockerUsername);
            environment.put("INSPECTOR_SBOMGEN_PASSWORD", dockerPassword);
        }

        builder.redirectErrorStream(true);
        Process p = null;

        try {
            p = builder.start();
        } catch (IOException e) {
            throw new BomermanNotFoundException(String.format("There was an issue running inspector-sbomgen, " +
                    "is %s the correct path?", bomermanPath));
        }

        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        StringBuilder sb = new StringBuilder();
        while (true) {
            line = r.readLine();
            sb.append(line + "\n");
            if (line == null) { break; }
        }

        return stripProperties(processBomermanOutput(sb.toString()));
    }
}