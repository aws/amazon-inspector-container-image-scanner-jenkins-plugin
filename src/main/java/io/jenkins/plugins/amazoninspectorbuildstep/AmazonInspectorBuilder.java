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
import io.jenkins.plugins.amazoninspectorbuildstep.bomerman.BomermanJarHandler;
import io.jenkins.plugins.amazoninspectorbuildstep.bomerman.BomermanRunner;
import io.jenkins.plugins.amazoninspectorbuildstep.credentials.CredentialsHelper;
import io.jenkins.plugins.amazoninspectorbuildstep.csvconversion.CsvConverter;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Sbom;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.SbomData;
import io.jenkins.plugins.amazoninspectorbuildstep.requests.Requests;
import io.jenkins.plugins.amazoninspectorbuildstep.requests.SdkRequests;
import io.jenkins.plugins.amazoninspectorbuildstep.sbomparsing.Results;
import io.jenkins.plugins.amazoninspectorbuildstep.sbomparsing.SbomOutputParser;
import io.jenkins.plugins.amazoninspectorbuildstep.sbomparsing.Severity;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.kohsuke.stapler.DataBoundConstructor;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;

import static io.jenkins.plugins.amazoninspectorbuildstep.utils.BomermanProcessing.processBomermanFile;
import static io.jenkins.plugins.amazoninspectorbuildstep.utils.InspectorRegions.BETA_REGIONS;


public class AmazonInspectorBuilder extends Builder implements SimpleBuildStep {
    private final String archivePath;
    private final String iamRole;
    private final String awsRegion;
    private final int countCritical;
    private final int countHigh;
    private final int countMedium;
    private final int countLow;
    private final boolean csvOutput;
    private final boolean jsonOutput;
    private final static String BOMERMAN_JAR_PATH_FORMAT =
            "%s/plugins/amazon-inspector-scanner/WEB-INF/lib/amazon-inspector-scanner.jar";
    private final static String BOMERMAN_SRC_PATH_FORMAT = "%s/../src/main/resources/bomerman";
    private Job<?, ?> job;

    @DataBoundConstructor
    public AmazonInspectorBuilder(String archivePath, String iamRole, String awsRegion, boolean csvOutput,
                                  boolean jsonOutput, int countCritical, int countHigh, int countMedium, int countLow) {
        this.archivePath = archivePath;
        this.iamRole = iamRole;
        this.awsRegion = awsRegion;
        this.csvOutput = csvOutput;
        this.jsonOutput = jsonOutput;
        this.countCritical = countCritical;
        this.countHigh = countHigh;
        this.countMedium = countMedium;
        this.countLow = countLow;
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
            String jarPath = new File(AmazonInspectorBuilder.class.getProtectionDomain().getCodeSource().getLocation()
                    .toURI()).getPath();
            String jenkinsRootPath = Jenkins.getInstanceOrNull().get().getRootDir().getAbsolutePath();
            String bomermanPath = new BomermanJarHandler(jarPath).copyBomermanToDir(jenkinsRootPath);

            String sbom = new BomermanRunner(bomermanPath, archivePath).run();

            listener.getLogger().println("Sending SBOM to Inspector for validation");
            SdkRequests requests = new SdkRequests(awsRegion, iamRole);

            listener.getLogger().println("Translating to SBOM data.");
            String responseData = requests.requestSbom(sbom).toString();

            SbomData sbomData = SbomData.builder().sbom(new Gson().fromJson(responseData, Sbom.class)).build();
            String sbomFileName = String.format("%s-%s.json", build.getParent().getDisplayName(),
                    build.getDisplayName()).replaceAll("[ #]", "");
            String sbomPath = String.format("%s/%s", build.getRootDir().getAbsolutePath(), sbomFileName);
            writeSbomDataToFile(responseData, sbomPath);

            CsvConverter converter = new CsvConverter(sbomData);
            String csvFileName = String.format("%s-%s.csv", build.getParent().getDisplayName(),
                    build.getDisplayName()).replaceAll("[ #]", "");;
            String csvPath = String.format("%s/%s", build.getRootDir().getAbsolutePath(), csvFileName);
            converter.convert(csvPath);

            SbomOutputParser parser = new SbomOutputParser(sbomData);
            Results results = parser.parseSbom();

            listener.getLogger().printf("CSV Output File: file://%s\n", csvPath.replace(" ", "%20"));
            listener.getLogger().printf("JSON Output File: file://%s\n", sbomPath.replace(" ", "%20"));

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

    public static void writeSbomDataToFile(String sbomData, String outputFilePath) {
        try (PrintWriter writer = new PrintWriter(new FileWriter(outputFilePath))) {
            for (String line : sbomData.split("\n")) {
                writer.println(line);
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
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

            for (String region : BETA_REGIONS) {
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
