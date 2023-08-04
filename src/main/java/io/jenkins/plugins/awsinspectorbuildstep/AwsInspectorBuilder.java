package io.jenkins.plugins.awsinspectorbuildstep;

import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractProject;
import hudson.model.Result;
import hudson.util.ArgumentListBuilder;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.Builder;
import hudson.tasks.BuildStepDescriptor;
import io.jenkins.plugins.awsinspectorbuildstep.dockerutils.DockerRepositoryArchiver;
import io.jenkins.plugins.awsinspectorbuildstep.sbomparsing.Results;
import io.jenkins.plugins.awsinspectorbuildstep.sbomparsing.Severity;

import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;


public class AwsInspectorBuilder extends Builder implements SimpleBuildStep {
    private final String localImage;
    private final String remoteImage;
    private final String archivePath;
    private final String imageType;
    private final int countCritical;
    private final int countHigh;
    private final int countMedium;
    private final int countLow;

    @DataBoundConstructor
    public AwsInspectorBuilder(String localImage, String remoteImage, String archivePath, String imageType,
                               int countCritical, int countHigh, int countMedium, int countLow) {
        this.localImage = localImage;
        this.remoteImage = remoteImage;
        this.archivePath = archivePath;
        this.imageType = imageType;
        this.countCritical = countCritical;
        this.countHigh = countHigh;
        this.countMedium = countMedium;
        this.countLow = countLow;
    }

    public String isImageType(String type) {
        if (this.imageType == null) {
            // default for new step GUI
            return "local".equals(type) ? "true" : "false";
        } else {
            return this.imageType.equals(type) ? "true" : "false";
        }
    }

    private String getBomermanPath(Jenkins jenkins) {
        String jenkinsRoot = jenkins.getInstanceOrNull().get().getRootDir().getAbsolutePath();
        return String.format("%s/../bomerman", jenkinsRoot);
    }


    private String getArtifactName(String imageType, TaskListener listener) {
        String artifactName = "bomerman_results";

        switch (imageType) {
                case "local":
                    // archive local image
                    artifactName += "-local.json";
                    break;
                case "remote":
                    // Pull remote image from repo & archive it, then use local
                    artifactName += "-remote.json";
                    break;
                case "dockerarchive":
                    artifactName += "-tar.json";
                    break;
                default:
                    listener.getLogger().println("unknown option");
            }

            return artifactName;
    }

    private boolean doesBuildFail(Map<Severity, Integer> counts) {
        boolean criticalExceedsLimit = counts.get(Severity.CRITICAL) > countCritical;
        boolean highExceedsLimit = counts.get(Severity.HIGH) > countCritical;
        boolean mediumExceedsLimit = counts.get(Severity.MEDIUM) > countCritical;
        boolean lowExceedsLimit = counts.get(Severity.LOW) > countCritical;
        
        return criticalExceedsLimit || highExceedsLimit || mediumExceedsLimit || lowExceedsLimit;
    }

    private void startProcess(Launcher launcher, ArgumentListBuilder args, PrintStream printStream)
            throws IOException, InterruptedException {
        Launcher.ProcStarter ps = launcher.launch();
        ps.cmds(args);
        ps.stdin(null);
        ps.stderr(printStream);
        ps.stdout(printStream);
        ps.quiet(true);
        ps.join();
    }

    @Override
    public void perform(Run<?, ?> build, FilePath workspace, EnvVars env, Launcher launcher, TaskListener listener) {
        PrintStream printStream = null;

        try {
            ArgumentListBuilder args = new ArgumentListBuilder();

            String bomermanPath = getBomermanPath(Jenkins.getInstanceOrNull().get());
            System.out.printf("Got bomerman path: %s", bomermanPath);
            args.add(bomermanPath, "container");
            String path = archivePath;

            if (imageType.equals("local")) {
                DockerRepositoryArchiver archiver = new DockerRepositoryArchiver(localImage, listener.getLogger());
                File destinationFile = archiver.createArchiveDestination(workspace.getRemote());
                path = archiver.archiveRepo(destinationFile);
            }

            args.add("--img", path);

            String artifactName = getArtifactName(imageType, listener);
            
            listener.getLogger().println(args);
            
            FilePath target = new FilePath(workspace, artifactName);
            File outFile = new File(build.getRootDir(), "out");

            printStream = new PrintStream(outFile, StandardCharsets.UTF_8);
            startProcess(launcher, args, printStream);
            FilePath outFilePath = new FilePath(outFile);
            outFilePath.copyTo(target);

            // send SBOM to API for analysis
            // ref: https://github.com/jenkinsci/rapid7-insightvm-container-assessment-plugin/blob/master/src/main/java/com/rapid7/sdlc/plugin/jenkins/ContainerAssessmentBuilder.java
            // ref: https://github.com/jenkinsci/qualys-cs-plugin/tree/master/src/main/java/com/qualys/plugins/containerSecurity

            Results results = new Results();
            boolean doesBuildPass = !doesBuildFail(results.getCounts());
            listener.getLogger().printf("Results: %s\nDoes Build Pass: %s\n",
                    results, doesBuildPass);

            if (doesBuildPass) {
                build.setResult(Result.SUCCESS);
            } else {
                build.setResult(Result.FAILURE);
            }

        } catch (RuntimeException e) {
            listener.getLogger().println("RuntimeException:" + e.toString());

        } catch (Exception e) {
            listener.getLogger().println("Exception:" + e.toString());
        } finally {
            if (printStream != null) {
                printStream.close();
            }
        }
    }


    @Symbol("AWS Inspector")
    @Extension
    public static class DescriptorImpl extends BuildStepDescriptor<Builder> {

        public DescriptorImpl() {
            load();
        }

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return "AWS Inspector Scan";
        }
    }
}
