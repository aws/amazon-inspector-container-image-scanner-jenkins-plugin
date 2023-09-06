package io.jenkins.plugins.amazoninspectorbuildstep;

import com.amazonaws.auth.AWSSessionCredentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.google.gson.Gson;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractProject;
import hudson.model.Job;
import hudson.model.Result;
import hudson.security.ACL;
import hudson.util.ArgumentListBuilder;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.Builder;
import hudson.tasks.BuildStepDescriptor;
import hudson.util.ListBoxModel;
import io.jenkins.plugins.amazoninspectorbuildstep.credentials.CredentialsHelper;
import io.jenkins.plugins.amazoninspectorbuildstep.csvconversion.CsvConverter;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.SbomData;
import io.jenkins.plugins.amazoninspectorbuildstep.requests.Requests;
import io.jenkins.plugins.amazoninspectorbuildstep.sbomparsing.Results;
import io.jenkins.plugins.amazoninspectorbuildstep.sbomparsing.SbomOutputParser;
import io.jenkins.plugins.amazoninspectorbuildstep.sbomparsing.Severity;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.kohsuke.stapler.DataBoundConstructor;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;

import static io.jenkins.plugins.amazoninspectorbuildstep.utils.InspectorRegions.INSPECTOR_REGIONS;


public class AmazonInspectorBuilder extends Builder implements SimpleBuildStep {
    private final String archivePath;
    private final String iamRole;
    private final String accessKeyId;
    private final String secretKeyId;
    private final String sessionTokenId;
    private final String awsRegion;
    private final int countCritical;
    private final int countHigh;
    private final int countMedium;
    private final int countLow;
    private final boolean csvOutput;
    private final boolean jsonOutput;
    private Job<?, ?> job;

    @DataBoundConstructor
    public AmazonInspectorBuilder(String archivePath, String iamRole, String accessKeyId, String secretKeyId,
                                  String sessionTokenId, String awsRegion, boolean csvOutput, boolean jsonOutput,
                                  int countCritical, int countHigh, int countMedium, int countLow) {
        this.archivePath = archivePath;
        this.iamRole = iamRole;
        this.accessKeyId = accessKeyId;
        this.secretKeyId = secretKeyId;
        this.sessionTokenId = sessionTokenId;
        this.awsRegion = awsRegion;
        this.csvOutput = csvOutput;
        this.jsonOutput = jsonOutput;
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
    public void perform(Run<?, ?> build, FilePath workspace, EnvVars env, Launcher launcher, TaskListener listener)
            throws IOException {
        File outFile = new File(build.getRootDir(), "out");
        this.job = build.getParent();

        PrintStream printStream =  new PrintStream(outFile, StandardCharsets.UTF_8);

        try {
            ArgumentListBuilder args = new ArgumentListBuilder();

            String bomermanPath = getBomermanPath(Jenkins.getInstanceOrNull().get());
            args.add(bomermanPath, "container", "--image", archivePath);
            String artifactName = String.format("%s-%s-bomerman_results-out.json", build.getParent().getDisplayName(),
                    build.getDisplayName()).replaceAll("[ #]", "");

            FilePath target = new FilePath(workspace, artifactName);

            listener.getLogger().println(args);
            startProcess(launcher, args, printStream);
            FilePath outFilePath = new FilePath(outFile);
            outFilePath.copyTo(target);

            String sbom = processBomermanFile(listener.getLogger(), outFile);

            Requests requests = createRequestsHelper(listener.getLogger(), build.getParent(), sbom);

            listener.getLogger().println("Translating to SBOM data.");
            String responseData = requests.requestSbom();
            SbomData sbomData = new Gson().fromJson(responseData, SbomData.class);
            String sbomFileName = String.format("%s-%s.json", build.getParent().getDisplayName(),
                    build.getDisplayName()).replaceAll("[ #]", "");
            String sbomPath = String.format("%s/%s", build.getRootDir().getAbsolutePath(), sbomFileName);
            writeSbomDataToFile(responseData, sbomPath);

            CsvConverter converter = new CsvConverter(listener.getLogger(), sbomData);
            String csvFileName = String.format("%s-%s.csv", build.getParent().getDisplayName(),
                    build.getDisplayName()).replaceAll("[ #]", "");;
            String csvPath = String.format("%s/%s", build.getRootDir().getAbsolutePath(), csvFileName);
            converter.convert(csvPath);

            SbomOutputParser parser = new SbomOutputParser(sbomData);
            Results results = parser.parseSbom();

            if (csvOutput) {
                listener.getLogger().printf("CSV Output File: file://%s\n", csvPath.replace(" ", "%20"));
            }

            if (jsonOutput) {
                listener.getLogger().printf("JSON Output File: file://%s\n", sbomPath.replace(" ", "%20"));
            }

            boolean doesBuildPass = !doesBuildFail(results.getCounts());
            listener.getLogger().printf("Results: %s\nDoes Build Pass: %s\n",
                    results, doesBuildPass);

            if (doesBuildPass) {
                build.setResult(Result.SUCCESS);
            } else {
                build.setResult(Result.FAILURE);
            }

        } catch (Exception e) {
            listener.getLogger().println("Plugin execution ran into an error and is being aborted!");
            build.setResult(Result.ABORTED);
            listener.getLogger().println("Exception:" + e);
            e.printStackTrace(listener.getLogger());
        } finally {
            if (printStream != null) {
                printStream.close();
            }
        }
    }

    private Requests createRequestsHelper(PrintStream logger, Job<?,?> parent, String sbom) {
        CredentialsHelper provider = new CredentialsHelper(logger, parent, "us-east-1");

        AwsBasicCredentials basicCreds = null;
        String sessionToken = null;

        if (iamRole != null && iamRole.length() > 0) {
            logger.printf("Using IAM Role %s\n", iamRole);
            AWSSessionCredentials sessionCredentials = provider.getCredentialsFromRole(iamRole);
            basicCreds = AwsBasicCredentials.create(sessionCredentials.getAWSAccessKeyId(),
                    sessionCredentials.getAWSSecretKey());
            sessionToken = sessionCredentials.getSessionToken();
        } else {
            logger.println("Using temporary credentials.");
            basicCreds = AwsBasicCredentials.create(provider.getKeyFromStore(accessKeyId),
                    provider.getKeyFromStore(secretKeyId));
            sessionToken = provider.getKeyFromStore(this.sessionTokenId);
        }

        return new Requests(basicCreds, sessionToken, sbom, logger, awsRegion);
    }

    public static int findBomermanStartLineIndex(List<String> list) {
        for (int i = 0; i < list.size(); i++) {
            if (list.get(i).length() > 0 && list.get(i).charAt(0) == '{') {
                return i;
            }
        }

        return -1;
    }

    public static void writeSbomDataToFile(String sbomData, String outputFilePath) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(outputFilePath))) {
            for (String line : sbomData.split("\n")) {
                writer.println(line);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static String processBomermanFile(PrintStream logger, File outFile) throws IOException {
        String rawFileContent = new String(new FileInputStream(outFile).readAllBytes(), StandardCharsets.UTF_8);

        String[] splitRawFileContent = rawFileContent.split("\n");
        List<String> lines = new ArrayList<>();
        for (String line : splitRawFileContent) {
            lines.add(line);
        }

        lines = lines.subList(findBomermanStartLineIndex(lines), lines.size());
        lines.add("\n}");
        lines.add(0, "{\n\"output\": \"DEFAULT\",\n\"sbom\":");

        return String.join("\n", lines);
    }

    @Symbol("Amazon Inspector")
    @Extension
    public static class DescriptorImpl extends BuildStepDescriptor<Builder> {
        public DescriptorImpl() {
            load();
        }

        private ListBoxModel getCredentialModels() {
            ListBoxModel items = new ListBoxModel();
            List<StringCredentials> credentials = CredentialsProvider.lookupCredentials(
                    StringCredentials.class,
                    Jenkins.getInstance(),
                    ACL.SYSTEM,
                    Collections.emptyList()
            );

            items.add("Select Credential ID", null);
            for (StringCredentials credential : credentials) {
                items.add(credential.getId(), credential.getId());
            }

            return items;
        }

        public ListBoxModel doFillAccessKeyIdItems() {
            return getCredentialModels();
        }

        public ListBoxModel doFillSecretKeyIdItems() {
            return getCredentialModels();
        }

        public ListBoxModel doFillSessionTokenIdItems() {
            return getCredentialModels();
        }

        public ListBoxModel doFillAwsRegionItems() {
            ListBoxModel items = new ListBoxModel();

            items.add("Select AWS Region", null);

            for (String region : INSPECTOR_REGIONS) {
                items.add(region, region);
            }

            return items;
        }

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return "Amazon Inspector Scan";
        }
    }
}
