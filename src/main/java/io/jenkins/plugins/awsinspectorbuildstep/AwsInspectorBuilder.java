package io.jenkins.plugins.awsinspectorbuildstep;

import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl;
import com.google.gson.Gson;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractProject;
import hudson.model.Item;
import hudson.model.Result;
import hudson.security.ACL;
import hudson.util.ArgumentListBuilder;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.Builder;
import hudson.tasks.BuildStepDescriptor;
import hudson.util.ListBoxModel;
import io.jenkins.plugins.awsinspectorbuildstep.credentials.CredentialsHelper;
import io.jenkins.plugins.awsinspectorbuildstep.csvconversion.CsvConverter;
import io.jenkins.plugins.awsinspectorbuildstep.dockerutils.DockerRepositoryArchiver;
import io.jenkins.plugins.awsinspectorbuildstep.dockerutils.EcrImagePuller;
import io.jenkins.plugins.awsinspectorbuildstep.models.sbom.Components.Vulnerability;
import io.jenkins.plugins.awsinspectorbuildstep.models.sbom.SbomData;
import io.jenkins.plugins.awsinspectorbuildstep.requests.Requests;
import io.jenkins.plugins.awsinspectorbuildstep.sbomparsing.Results;
import io.jenkins.plugins.awsinspectorbuildstep.sbomparsing.SbomOutputParser;
import io.jenkins.plugins.awsinspectorbuildstep.sbomparsing.Severity;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;


public class AwsInspectorBuilder extends Builder implements SimpleBuildStep {
    private final String archivePath;
    private final String accessKeyId;
    private final String secretKeyId;
    private final String sessionTokenId;
    private final int countCritical;
    private final int countHigh;
    private final int countMedium;
    private final int countLow;

    @DataBoundConstructor
    public AwsInspectorBuilder(String archivePath,
                               String accessKeyId, String secretKeyId, String sessionTokenId, int countCritical,
                               int countHigh, int countMedium, int countLow) {
        this.archivePath = archivePath;
        this.accessKeyId = accessKeyId;
        this.secretKeyId = secretKeyId;
        this.sessionTokenId = sessionTokenId;
        this.countCritical = countCritical;
        this.countHigh = countHigh;
        this.countMedium = countMedium;
        this.countLow = countLow;
    }

    private String getBomermanPath(Jenkins jenkins) {
        String jenkinsRoot = jenkins.getInstanceOrNull().get().getRootDir().getAbsolutePath();
        return String.format("%s/../bomerman15", jenkinsRoot);
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

            args.add(bomermanPath, "container", "--image", archivePath);

            String artifactName = "bomerman_results-out.json";

            FilePath target = new FilePath(workspace, artifactName);
            File outFile = new File(build.getRootDir(), "out");

            printStream = new PrintStream(outFile, StandardCharsets.UTF_8);
            listener.getLogger().println(args);
            startProcess(launcher, args, printStream);
            FilePath outFilePath = new FilePath(outFile);
            outFilePath.copyTo(target);

            String sbom = processBomermanFile(listener.getLogger(), outFile);

            CredentialsHelper provider = new CredentialsHelper(listener.getLogger(), build.getParent(), "us-east-1");
            AwsBasicCredentials basicCreds = AwsBasicCredentials.create(provider.getKeyFromStore(accessKeyId),
                    provider.getKeyFromStore(secretKeyId));
            Requests requests = new Requests(basicCreds, provider.getKeyFromStore(sessionTokenId),
                    sbom, listener.getLogger());

            listener.getLogger().println("Trasnlating to sbomdata");
            String responseData = requests.getSbom();
            SbomData sbomData = new Gson().fromJson(responseData, SbomData.class);
//            CsvConverter converter = new CsvConverter(listener.getLogger(), sbomData);
//            String fileName = String.format("%scsv.csv", imageId);
//            converter.convert(String.format("%s/%s", build.getRootDir().getAbsolutePath(), fileName));

            SbomOutputParser parser = new SbomOutputParser(sbomData);
            Results results = parser.parseSbom();

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
            e.printStackTrace();
        } catch (Exception e) {
            listener.getLogger().println("Exception:" + e.toString());
            e.printStackTrace();
        } finally {
            if (printStream != null) {
                printStream.close();
            }
        }
    }

    public static int findStartIndex(List<String> list) {
        for (int i = 0; i < list.size(); i++) {
            if (list.get(i).length() > 0 && list.get(i).charAt(0) == '{') {
                return i;
            }
        }

        return -1;
    }

    public static String processBomermanFile(PrintStream logger, File outFile) throws IOException {
        String rawFileContent = new String(new FileInputStream(outFile).readAllBytes(), StandardCharsets.UTF_8);
        logger.println(rawFileContent);
        String[] splitRawFileContent = rawFileContent.split("\n");
        List<String> lines = new ArrayList<>();
        for (String line : splitRawFileContent) {
            lines.add(line);
        }

        lines = lines.subList(findStartIndex(lines), lines.size());
        lines.add("\n}");
        lines.add(0, "{\n\"output\": \"DEFAULT\",\n\"sbom\":");

        return String.join("\n", lines);
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
