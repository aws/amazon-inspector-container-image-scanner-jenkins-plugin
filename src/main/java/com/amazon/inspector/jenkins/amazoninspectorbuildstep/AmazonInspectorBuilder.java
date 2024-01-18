package com.amazon.inspector.jenkins.amazoninspectorbuildstep;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen.SbomgenDownloader;
import com.cloudbees.jenkins.plugins.awscredentials.AmazonWebServicesCredentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
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

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen.SbomgenRunner;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.csvconversion.CsvConverter;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.html.HtmlGenerator;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.html.HtmlJarHandler;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.html.HtmlData;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.html.components.ImageMetadata;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.html.components.SeverityValues;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Sbom;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.SbomData;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.requests.SdkRequests;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomparsing.SbomOutputParser;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomparsing.Severity;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomparsing.SeverityCounts;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils.HtmlConversionUtils;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import lombok.Getter;
import net.sf.json.JSONObject;
import org.apache.commons.lang.StringEscapeUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.verb.POST;

import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils.InspectorRegions.INSPECTOR_REGIONS;
import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils.Sanitizer.sanitizeFilePath;
import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils.Sanitizer.sanitizeText;
import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils.Sanitizer.sanitizeUrl;
import static hudson.security.Permission.READ;

@Getter
public class AmazonInspectorBuilder extends Builder implements SimpleBuildStep {
    @SuppressFBWarnings()
    public static PrintStream logger;
    private final String sbomgenMethod;
    private final String archivePath;
    private final String iamRole;
    private final String awsRegion;
    private final String credentialId;
    private final boolean isThresholdEnabled;
    private final String sbomgenPath;
    private final String sbomgenSource;
    private final boolean osArch;
    private final int countCritical;
    private final int countHigh;
    private final int countMedium;
    private final int countLow;
    private final String awsCredentialId;
    private Job<?, ?> job;

    @DataBoundConstructor
    public AmazonInspectorBuilder(String archivePath, String sbomgenPath, boolean osArch, String iamRole, String awsRegion,
                                  String credentialId, String awsCredentialId, String sbomgenMethod, String sbomgenSource,
                                  boolean isThresholdEnabled, int countCritical, int countHigh, int countMedium,
                                  int countLow) {
        this.archivePath = archivePath;
        this.credentialId = credentialId;
        this.awsCredentialId = awsCredentialId;
        this.sbomgenSource = sbomgenSource;
        this.sbomgenPath = sbomgenPath;
        this.sbomgenMethod = sbomgenMethod;
        this.osArch = osArch;
        this.iamRole = iamRole;
        this.awsRegion = awsRegion;
        this.isThresholdEnabled = isThresholdEnabled;
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

    public String isSource(String value) {
        return Boolean.toString(sbomgenMethod.equals(value));
    }

    @Override
    public void perform(Run<?, ?> build, FilePath workspace, EnvVars env, Launcher launcher, TaskListener listener)
            throws IOException {
        logger = listener.getLogger();

        File outFile = new File(build.getRootDir(), "out");
        this.job = build.getParent();

        PrintStream printStream = new PrintStream(outFile, StandardCharsets.UTF_8);
        try {
            if (Jenkins.getInstanceOrNull() == null) {
                throw new RuntimeException("No Jenkins instance found");
            }

            String activeSbomgenPath = sbomgenPath;
            if (sbomgenSource != null && !sbomgenSource.isEmpty()) {
                logger.println("Automatic SBOMGen Sourcing selected, downloading now...");
                activeSbomgenPath = SbomgenDownloader.getBinary(sbomgenSource);
            } else {
                build.getEnvironment(listener).put("sbomgenPath", activeSbomgenPath);
            }

            StandardUsernamePasswordCredentials credential = null;
            if (credentialId == null) {
                logger.println("Credential ID is null, this is not normal, please check your config. " +
                        "Continuing without docker credentials.");
            } else {
                credential = CredentialsProvider.findCredentialById(credentialId,
                        StandardUsernamePasswordCredentials.class, build);
            }

            String sbom;
            if (credential != null) {
                logger.println("Running inspector-sbomgen with docker credential: " + credential.getId());
                sbom = new SbomgenRunner(activeSbomgenPath, archivePath, credential.getUsername(),
                        credential.getPassword().getPlainText()).run();
            } else {
                logger.println("No credential provided, running without.");
                sbom = new SbomgenRunner(activeSbomgenPath, archivePath, null, null).run();
            }

            JsonObject component = JsonParser.parseString(sbom).getAsJsonObject().get("metadata").getAsJsonObject()
                    .get("component").getAsJsonObject();

            Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
            String imageSha = getImageSha(sbom);

            listener.getLogger().print("Sending SBOM to Inspector for validation ");
            if (awsCredentialId != null) {
                listener.getLogger().print("with credential:" + awsCredentialId);
            }
            listener.getLogger().print("\n");

            AmazonWebServicesCredentials awsCredential = CredentialsProvider.findCredentialById(awsCredentialId,
                    AmazonWebServicesCredentials.class, build);

            String responseData = new SdkRequests(awsRegion, awsCredential, iamRole).requestSbom(sbom);

            SbomData sbomData = SbomData.builder().sbom(gson.fromJson(responseData, Sbom.class)).build();

            String artifactDestinationPath = build.getArtifactsDir().getAbsolutePath();
            new File(artifactDestinationPath).mkdirs();

            String sbomFileName = String.format("%s-%s-sbom.json", build.getParent().getDisplayName(),
                    build.getDisplayName()).replaceAll("[ #]", "");
            String sbomPath = String.format("%s/%s", artifactDestinationPath, sbomFileName);

            writeSbomDataToFile(gson.toJson(sbomData.getSbom()), sbomPath);

            CsvConverter converter = new CsvConverter(sbomData);
            String csvFileName = String.format("%s-%s.csv", build.getParent().getDisplayName(),
                    build.getDisplayName()).replaceAll("[ #]", "");
            String csvPath = String.format("%s/%s", artifactDestinationPath, csvFileName);

            logger.println("Converting SBOM Results to CSV.");
            converter.convert(csvPath);

            SbomOutputParser parser = new SbomOutputParser(sbomData);
            SeverityCounts severityCounts = parser.parseSbom();

            String sanitizedImageId = null;
            String componentName = component.get("name").getAsString();

            if (componentName.endsWith(".tar")) {
                sanitizedImageId = sanitizeFilePath("file://" + componentName);
            } else {
                sanitizedImageId = sanitizeText(componentName);
            }

            String[] splitName = sanitizedImageId.split(":");
            String tag = null;
            if (splitName.length > 1) {
                tag = splitName[1];
            }

            String outputWorkspacePath = String.format("%sjob/%s/%s/artifact", env.get("JENKINS_URL"), env.get("JOB_NAME"),
                    env.get("BUILD_NUMBER"));

            HtmlData htmlData = HtmlData.builder()
                    .jsonFilePath(sanitizeUrl(outputWorkspacePath + "/" + sbomFileName))
                    .csvFilePath(sanitizeUrl(outputWorkspacePath + "/" + csvFileName))
                    .imageMetadata(ImageMetadata.builder()
                            .id(splitName[0])
                            .tags(tag)
                            .sha(imageSha)
                            .build())
                    .severityValues(SeverityValues.builder()
                            .critical(severityCounts.getCounts().get(Severity.CRITICAL))
                            .high(severityCounts.getCounts().get(Severity.HIGH))
                            .medium(severityCounts.getCounts().get(Severity.MEDIUM))
                            .low(severityCounts.getCounts().get(Severity.LOW))
                            .build())
                    .vulnerabilities(HtmlConversionUtils.convertVulnerabilities(sbomData.getSbom().getVulnerabilities(),
                            sbomData.getSbom().getComponents()))
                    .build();

            String htmlJarPath = new File(HtmlJarHandler.class.getProtectionDomain().getCodeSource().getLocation()
                    .toURI()).getPath();
            HtmlJarHandler htmlJarHandler = new HtmlJarHandler(htmlJarPath);

            String htmlPath = htmlJarHandler.copyHtmlToDir(artifactDestinationPath);

            String html = new Gson().toJson(htmlData);
            new HtmlGenerator(htmlPath).generateNewHtml(html);

            logger.println("Prefixing file paths with Jenkins URL from settings, currently: " + env.get("JENKINS_URL"));

            listener.getLogger().println("CSV Output File: " + sanitizeUrl(outputWorkspacePath + "/" + csvFileName));
            listener.getLogger().println("SBOM Output File: " + sanitizeUrl(outputWorkspacePath + "/" + sbomFileName));
            listener.getLogger().println("HTML Report File: " + outputWorkspacePath + "/index.html");
            listener.getLogger().println("Alternate Report Link: file://" + htmlPath);
            boolean doesBuildPass = !doesBuildFail(severityCounts.getCounts());

            if (!isThresholdEnabled) {
                build.setResult(Result.SUCCESS);
                doesBuildPass = true;
            } else if (isThresholdEnabled && doesBuildPass) {
                build.setResult(Result.SUCCESS);
            } else {
                build.setResult(Result.FAILURE);
            }

            listener.getLogger().println("Results: " + severityCounts);
            if (!isThresholdEnabled) {
                listener.getLogger().println("Ignoring results due to thresholds being disabled.");
            }

            listener.getLogger().println("Does Build Pass: " + doesBuildPass);

        } catch (Exception e) {
            listener.getLogger().println("Plugin execution ran into an error and is being aborted!");
            build.setResult(Result.ABORTED);
            listener.getLogger().println("Exception:" + e);
            e.printStackTrace(listener.getLogger());
        } finally {
            printStream.close();
        }
    }

    public static String getImageSha(String sbom) {
        JsonElement jsonElement = JsonParser.parseString(sbom);
        JsonArray properties = jsonElement.getAsJsonObject().get("metadata")
                .getAsJsonObject().get("component")
                .getAsJsonObject().get("properties")
                .getAsJsonArray();

        for (JsonElement property : properties) {
            if (property.getAsJsonObject().get("name").getAsString().equals("amazon:inspector:sbom_generator:image_id")) {
                return property.getAsJsonObject().get("value").getAsString();
            }
        }

        return "No Sha Found";
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

        @Override
        public AmazonInspectorBuilder newInstance(StaplerRequest req, JSONObject formData) throws FormException {
            String value = JSONObject.fromObject(formData.get("sbomgenSelection")).get("value").toString();
            formData.put("isAutomaticSbomgen", value.equals("automatic"));
            formData.put("sbomgenMethod", value);

            if (value.equals("manual")) {
                formData.put("sbomgenPath", JSONObject.fromObject(formData.get("sbomgenSelection")).get("sbomgenPath"));
            } else if (value.equals("automatic")) {
                formData.put("sbomgenSource", JSONObject.fromObject(JSONObject.fromObject(formData.get("sbomgenSelection")).get("sbomgenSource")).get("value"));
            }
            
            return req.bindJSON(AmazonInspectorBuilder.class, formData);
        }

        private ListBoxModel getCredentialIdModels() {
            ListBoxModel items = new ListBoxModel();
            List<StandardUsernamePasswordCredentials> credentials = CredentialsProvider.lookupCredentials(
                    StandardUsernamePasswordCredentials.class,
                    Jenkins.getInstance(),
                    ACL.SYSTEM,
                    Collections.emptyList()
            );

            items.add("Select Docker Username", null);
            for (StandardUsernamePasswordCredentials credential : credentials) {
                if (credential.getUsername() != null && !credential.getUsername().isEmpty()) {
                    items.add(String.format("[%s] %s/*****", credential.getId(), credential.getUsername()),
                            credential.getId());
                }
            }

            return items;
        }

        @POST
        public ListBoxModel doFillCredentialIdItems() {
            if (Jenkins.get().hasPermission(READ)) {
                return getCredentialIdModels();
            }
            return new ListBoxModel();
        }

        private ListBoxModel getAwsCredentialIdModels() {
            ListBoxModel items = new ListBoxModel();
            List<AmazonWebServicesCredentials> credentials = CredentialsProvider.lookupCredentials(
                    AmazonWebServicesCredentials.class,
                    Jenkins.getInstance(),
                    ACL.SYSTEM,
                    Collections.emptyList()
            );

            items.add("Select AWS Credentials", null);
            for (AmazonWebServicesCredentials credential : credentials) {
                if (credential.getCredentials() != null && !credential.getCredentials().getAWSAccessKeyId().isEmpty()) {
                    items.add(String.format("[%s] %s", credential.getId(), credential.getDisplayName()),
                            credential.getId());
                }
            }

            return items;
        }

        @POST
        public ListBoxModel doFillAwsCredentialIdItems() {
            if (Jenkins.get().hasPermission(READ)) {
                return getAwsCredentialIdModels();
            }
            return new ListBoxModel();
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
