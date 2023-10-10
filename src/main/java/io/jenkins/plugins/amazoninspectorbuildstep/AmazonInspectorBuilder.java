package io.jenkins.plugins.amazoninspectorbuildstep;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractProject;
import hudson.model.Job;
import hudson.model.Result;
import hudson.security.ACL;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.Builder;
import hudson.tasks.BuildStepDescriptor;
import hudson.util.ListBoxModel;
import io.jenkins.plugins.amazoninspectorbuildstep.bomerman.BomermanJarHandler;
import io.jenkins.plugins.amazoninspectorbuildstep.bomerman.BomermanRunner;
import io.jenkins.plugins.amazoninspectorbuildstep.csvconversion.CsvConverter;
import io.jenkins.plugins.amazoninspectorbuildstep.html.HtmlGenerator;
import io.jenkins.plugins.amazoninspectorbuildstep.html.HtmlJarHandler;
import io.jenkins.plugins.amazoninspectorbuildstep.models.html.HtmlData;
import io.jenkins.plugins.amazoninspectorbuildstep.models.html.components.ImageMetadata;
import io.jenkins.plugins.amazoninspectorbuildstep.models.html.components.SeverityValues;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Sbom;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.SbomData;
import io.jenkins.plugins.amazoninspectorbuildstep.requests.SdkRequests;
import io.jenkins.plugins.amazoninspectorbuildstep.sbomparsing.Results;
import io.jenkins.plugins.amazoninspectorbuildstep.sbomparsing.SbomOutputParser;
import io.jenkins.plugins.amazoninspectorbuildstep.sbomparsing.Severity;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import io.jenkins.plugins.amazoninspectorbuildstep.utils.HtmlConversionUtils;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import org.apache.commons.lang.StringEscapeUtils;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.kohsuke.stapler.DataBoundConstructor;

import static io.jenkins.plugins.amazoninspectorbuildstep.utils.InspectorRegions.BETA_REGIONS;


public class AmazonInspectorBuilder extends Builder implements SimpleBuildStep {
    public static PrintStream logger;
    private final String archivePath;
    private final String iamRole;
    private final String awsRegion;
    private final String dockerUsername;
    private final int countCritical;
    private final int countHigh;
    private final int countMedium;
    private final int countLow;
    private Job<?, ?> job;

    @DataBoundConstructor
    public AmazonInspectorBuilder(String archivePath, String iamRole, String awsRegion, String dockerUsername,
                                  int countCritical, int countHigh, int countMedium, int countLow) {
        this.archivePath = archivePath;
        this.dockerUsername = dockerUsername;
        this.iamRole = iamRole;
        this.awsRegion = awsRegion;
        this.countCritical = countCritical;
        this.countHigh = countHigh;
        this.countMedium = countMedium;
        this.countLow = countLow;
    }

    private boolean doesBuildFail(Map<Severity, Integer> counts) {
        boolean criticalExceedsLimit = counts.get(Severity.CRITICAL) > countCritical;
        boolean highExceedsLimit = counts.get(Severity.HIGH) > countHigh;
        boolean mediumExceedsLimit = counts.get(Severity.MEDIUM) > countMedium;
        boolean lowExceedsLimit = counts.get(Severity.LOW) > countLow;
        
        return criticalExceedsLimit || highExceedsLimit || mediumExceedsLimit || lowExceedsLimit;
    }

    @Override
    public void perform(Run<?, ?> build, FilePath workspace, EnvVars env, Launcher launcher, TaskListener listener)
            throws IOException {
        logger = listener.getLogger();

        File outFile = new File(build.getRootDir(), "out");
        this.job = build.getParent();

        PrintStream printStream =  new PrintStream(outFile, StandardCharsets.UTF_8);

        try {
            String jarPath = new File(AmazonInspectorBuilder.class.getProtectionDomain().getCodeSource().getLocation()
                    .toURI()).getPath();
            String jenkinsRootPath = Jenkins.getInstanceOrNull().get().getRootDir().getAbsolutePath();
            String bomermanPath = new BomermanJarHandler(jarPath).copyBomermanToDir(jenkinsRootPath);

            String sbom = new BomermanRunner(bomermanPath, archivePath, dockerUsername).run(job);

            JsonObject component = JsonParser.parseString(sbom).getAsJsonObject().get("metadata").getAsJsonObject()
                    .get("component").getAsJsonObject();

            String imageSha = "No Sha Found";
            for (JsonElement element : component.get("properties").getAsJsonArray()) {
                String elementName = element.getAsJsonObject().get("name").getAsString();
                if (elementName.equals("amazon:inspector:sbom_collector:image_id")) {
                    imageSha = element.getAsJsonObject().get("value").getAsString();
                }
            }

            listener.getLogger().println("Sending SBOM to Inspector for validation");
            SdkRequests requests = new SdkRequests(awsRegion, iamRole);

            listener.getLogger().println("Translating to SBOM data.");
            String responseData = requests.requestSbom(sbom).toString();
            responseData = responseData.replaceAll("\n", "");

            Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
            SbomData sbomData = SbomData.builder().sbom(gson.fromJson(responseData, Sbom.class)).build();

            String sbomFileName = String.format("%s-%s.json", build.getParent().getDisplayName(),
                    build.getDisplayName()).replaceAll("[ #]", "");
            String sbomPath = String.format("%s/%s", build.getRootDir().getAbsolutePath(), sbomFileName);

            writeSbomDataToFile(gson.toJson(sbomData.getSbom()), sbomPath);

            CsvConverter converter = new CsvConverter(sbomData);
            String csvFileName = String.format("%s-%s.csv", build.getParent().getDisplayName(),
                    build.getDisplayName()).replaceAll("[ #]", "");;
            String csvPath = String.format("%s/%s", build.getRootDir().getAbsolutePath(), csvFileName);
            converter.convert(csvPath);

            SbomOutputParser parser = new SbomOutputParser(sbomData);
            Results results = parser.parseSbom();

            String[] splitName = component.get("name").getAsString().split(":");
            String tag = null;
            if (splitName.length > 1) {
                tag = splitName[1];
            }

            HtmlData htmlData = HtmlData.builder()
                    .jsonFilePath(sbomPath)
                    .csvFilePath(csvPath)
                    .imageMetadata(ImageMetadata.builder()
                            .id(splitName[0])
                            .tags(tag)
                            .sha(imageSha)
                            .build())
                    .severityValues(SeverityValues.builder()
                            .critical(results.getCounts().get(Severity.CRITICAL))
                            .high(results.getCounts().get(Severity.HIGH))
                            .medium(results.getCounts().get(Severity.MEDIUM))
                            .low(results.getCounts().get(Severity.LOW))
                            .build())
                    .vulnerabilities(HtmlConversionUtils.convertVulnerabilities(sbomData.getSbom().getVulnerabilities(),
                            sbomData.getSbom().getComponents()))
                    .build();

            HtmlJarHandler htmlJarHandler = new HtmlJarHandler(jarPath);
            String htmlPath = htmlJarHandler.copyHtmlToDir(build.getRootDir().getAbsolutePath());

            String html = new Gson().toJson(htmlData);
            new HtmlGenerator(htmlPath).generateNewHtml(html);

            listener.getLogger().printf("CSV Output File: file://%s\n", csvPath.replace(" ", "%20"));
            listener.getLogger().printf("SBOM Output File: file://%s\n", sbomPath.replace(" ", "%20"));
            listener.getLogger().printf("HTML Report File: file://%s\n", htmlPath.replace(" ", "%20"));
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
                writer.println(StringEscapeUtils.unescapeJava(line));
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

        private ListBoxModel getStringCredentialModels() {
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

        private ListBoxModel getUsernameCredentialModels() {
            ListBoxModel items = new ListBoxModel();
            List<UsernamePasswordCredentials> credentials = CredentialsProvider.lookupCredentials(
                    UsernamePasswordCredentials.class,
                    Jenkins.getInstance(),
                    ACL.SYSTEM,
                    Collections.emptyList()
            );

            items.add("Select Docker Username", null);
            for (UsernamePasswordCredentials credential : credentials) {
                items.add(credential.getUsername(), credential.getUsername());
            }

            return items;
        }

        public ListBoxModel doFillAccessKeyIdItems() {
            return getStringCredentialModels();
        }

        public ListBoxModel doFillSecretKeyIdItems() {
            return getStringCredentialModels();
        }

        public ListBoxModel doFillSessionTokenIdItems() {
            return getStringCredentialModels();
        }

        public ListBoxModel doFillDockerUsernameItems() {
            return getUsernameCredentialModels();
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
            return "Amazon Inspector Scan - Beta";
        }
    }
}
