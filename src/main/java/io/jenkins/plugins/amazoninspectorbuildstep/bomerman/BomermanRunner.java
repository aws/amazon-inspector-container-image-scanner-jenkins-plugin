package io.jenkins.plugins.amazoninspectorbuildstep.bomerman;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class BomermanRunner {
    public String bomermanPath;
    public String archivePath;

    public BomermanRunner(String bomermanPath, String archivePath) {
        this.bomermanPath = bomermanPath;
        this.archivePath = archivePath;
    }

    public String run() throws IOException {
        return runBomerman(bomermanPath, archivePath);
    }

    private static String runBomerman(String bomermanPath, String archivePath) throws IOException {
        String[] command = new String[] {
                bomermanPath, "container", "--image", archivePath
        };

        ProcessBuilder builder = new ProcessBuilder(command);
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

        return BomermanUtils.processBomermanOutput(sb.toString());
    }
}
