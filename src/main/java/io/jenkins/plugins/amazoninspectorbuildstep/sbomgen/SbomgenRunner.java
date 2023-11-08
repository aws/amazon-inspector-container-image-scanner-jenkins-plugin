package io.jenkins.plugins.amazoninspectorbuildstep.sbomgen;

import com.google.common.annotations.VisibleForTesting;
import lombok.Setter;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Map;

import static io.jenkins.plugins.amazoninspectorbuildstep.AmazonInspectorBuilder.logger;
import static io.jenkins.plugins.amazoninspectorbuildstep.sbomgen.SbomgenUtils.processSbomgenOutput;
import static io.jenkins.plugins.amazoninspectorbuildstep.sbomgen.SbomgenUtils.stripProperties;

public class SbomgenRunner {
    public String sbomgenPath;
    public String archivePath;
    @Setter
    public static String dockerUsername;
    @Setter
    public String dockerPassword;

    public SbomgenRunner(String sbomgenPath, String archivePath, String dockerUsername) {
        this.sbomgenPath = sbomgenPath;
        this.archivePath = archivePath;
        this.dockerUsername = dockerUsername;
    }

    public SbomgenRunner(String sbomgenPath, String archivePath, String dockerUsername, String dockerPassword) {
        this.sbomgenPath = sbomgenPath;
        this.archivePath = archivePath;
        this.dockerUsername = dockerUsername;
        this.dockerPassword = dockerPassword;
    }

    public String run() throws Exception {
        return runSbomgen(sbomgenPath, archivePath);
    }

    private String runSbomgen(String sbomgenPath, String archivePath) throws Exception {
        if (!isValidPath(sbomgenPath)) {
            throw new IllegalArgumentException("Invalid sbomgen path: " + sbomgenPath);
        }

        if (!isValidPath(archivePath)) {
            throw new IllegalArgumentException("Invalid archive path: " + archivePath);
        }

        String[] command = new String[] {
                sbomgenPath, "container", "--image", archivePath
        };

        ProcessBuilder builder = new ProcessBuilder(command);
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

        return stripProperties(processSbomgenOutput(sb.toString()));
    }

    @VisibleForTesting
    protected boolean isValidPath(String path) {
        String regex = "^[a-zA-Z0-9/._\\-:]+$";
        return path.matches(regex);
    }
}