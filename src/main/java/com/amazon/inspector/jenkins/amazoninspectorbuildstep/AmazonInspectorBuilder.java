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
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen.SbomgenRunner;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.csvconversion.CsvConverter;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.html.HtmlJarHandler;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.html.HtmlData;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.html.components.ImageMetadata;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.html.components.SeverityValues;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Sbom;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.SbomData;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.requests.SdkRequests;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomparsing.SbomOutputParser;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomparsing.Severity;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomparsing.SeverityCounts;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils.HtmlConversionUtils;
import io.jenkins.plugins.oidc_provider.IdTokenFileCredentials;
import io.jenkins.plugins.oidc_provider.IdTokenStringCredentials;

import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import jenkins.util.BuildListenerAdapter;
import lombok.Getter;
import net.sf.json.JSONObject;
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
    private final String archiveType;
    private final String iamRole;
    private final String awsRegion;
    private final String credentialId;
    private final String oidcCredentialId;
    private final boolean isThresholdEnabled;
    private final String sbomgenPath;
    private final String sbomgenSource;
    private final boolean osArch;
    private final int countCritical;
    private final int countHigh;
    private final int countMedium;
    private final int countLow;
    private final String awsCredentialId;
    private final String awsProfileName;
    private Job<?, ?> job;

    @DataBoundConstructor
    public AmazonInspectorBuilder(String archivePath, String archiveType, String sbomgenPath, boolean osArch, String iamRole,
                                  String awsRegion, String credentialId, String awsProfileName, String awsCredentialId,
                                  String sbomgenMethod, String sbomgenSource, boolean isThresholdEnabled, int countCritical,
                                  int countHigh, int countMedium, int countLow, String oidcCredentialId) {
        this.archivePath = archivePath;
        this.archiveType = archiveType;
        this.credentialId = credentialId;
        this.awsCredentialId = awsCredentialId;
        this.oidcCredentialId = oidcCredentialId;
        this.awsProfileName = awsProfileName;
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

    public String isOs(String value) {
        return Boolean.toString(sbomgenMethod.equals("automatic") && sbomgenSource.equals(value));
    }

    @Override
    public void perform(Run<?, ?> build, FilePath workspace, EnvVars env, Launcher launcher, TaskListener listener)
            throws IOException {
        logger = listener.getLogger();

        File outFile = new File(build.getRootDir(), "out");
        this.job = build.getParent();

        PrintStream printStream = new PrintStream(outFile, StandardCharsets.UTF_8);
        try {
            Map<String, String> artifactMap = new HashMap<>();

            if (Jenkins.getInstanceOrNull() == null) {
                throw new RuntimeException("No Jenkins instance found.");
            }

            String activeArchiveType = archiveType;
            if (activeArchiveType == null || activeArchiveType.isEmpty()) {
                activeArchiveType = "container";
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
                sbom = new SbomgenRunner(activeSbomgenPath, activeArchiveType, archivePath, credential.getUsername(),
                        credential.getPassword().getPlainText()).run();
            } else {
                logger.println("No credential provided, running without.");
                sbom = new SbomgenRunner(activeSbomgenPath, activeArchiveType, archivePath, null, null).run();
            }

            JsonObject component = JsonParser.parseString(sbom).getAsJsonObject().get("metadata").getAsJsonObject()
                    .get("component").getAsJsonObject();

            Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
            String imageSha = getImageSha(sbom);

            listener.getLogger().printf("Sending SBOM to Inspector for validation with info: credential:%s, role:%s, profile:%s",
                    awsCredentialId, iamRole, awsProfileName);
            AmazonWebServicesCredentials awsCredential = null;
            if (awsCredentialId != null) {
                awsCredential = CredentialsProvider.findCredentialById(awsCredentialId,
                        AmazonWebServicesCredentials.class, build);
            }
            listener.getLogger().print("\n");

            String workingOidcCredentialId = oidcCredentialId;
            if (workingOidcCredentialId == null) {
                workingOidcCredentialId = "";
            }
            IdTokenStringCredentials oidcStr = CredentialsProvider.findCredentialById(workingOidcCredentialId, IdTokenStringCredentials.class, build);
            IdTokenFileCredentials oidcFile = CredentialsProvider.findCredentialById(workingOidcCredentialId, IdTokenFileCredentials.class, build);
            String oidcToken = getOidcToken(oidcStr, oidcFile);

            String responseData = new SdkRequests(awsRegion, awsCredential, oidcToken, awsProfileName, iamRole).requestSbom(sbom);

            SbomData sbomData = SbomData.builder().sbom(gson.fromJson(responseData, Sbom.class)).build();

            String sbomFileName = String.format("%s-%s-sbom.json", build.getParent().getDisplayName(),
                    build.getDisplayName()).replaceAll("[ #]", "");
            String sbomWorkspacePath = String.format("%s/%s", build.getId(), sbomFileName);
            artifactMap.put(sbomFileName, sbomWorkspacePath);
            FilePath sbomFile = workspace.child(sbomWorkspacePath);
            sbomFile.write(gson.toJson(sbomData.getSbom()), "UTF-8");

            CsvConverter converter = new CsvConverter(sbomData);
            String csvFileName = String.format("%s-%s.csv", build.getParent().getDisplayName(),
                    build.getDisplayName()).replaceAll("[ #]", "");
            String csvWorkspacePath = String.format("%s/%s", build.getId(), csvFileName);
            artifactMap.put(csvFileName, csvWorkspacePath);
            FilePath csvFile = workspace.child(csvWorkspacePath);
            logger.println("Converting SBOM Results to CSV.");

            SbomOutputParser parser = new SbomOutputParser(sbomData);
            SeverityCounts severityCounts = parser.parseSbom();

            String sanitizedImageId = null;
            String componentName = component.get("name").getAsString();

            if (componentName.endsWith(".tar")) {
                sanitizedImageId = sanitizeFilePath("file://" + componentName);
            } else {
                sanitizedImageId = sanitizeText(componentName);
            }
            String csvContent = converter.convert(sanitizedImageId, imageSha, build.getId(), severityCounts);
            csvFile.write(csvContent, "UTF-8");

            String[] splitName = sanitizedImageId.split(":");
            String tag = null;
            if (splitName.length > 1) {
                tag = splitName[1];
            }

            @SuppressFBWarnings
            HtmlData htmlData = HtmlData.builder()
                    .artifactsPath(sanitizeUrl(env.get("RUN_ARTIFACTS_DISPLAY_URL"))) //jenkins specific
                    .updatedAt(new SimpleDateFormat("MM/dd/yyyy, hh:mm:ss aa").format(Calendar.getInstance().getTime()))
                    .imageMetadata(ImageMetadata.builder()
                            .id(splitName[0])
                            .tags(tag)
                            .sha(imageSha)
                            .build())
                    .vulnerabilities(HtmlConversionUtils.convertVulnerabilities(sbomData.getSbom().getVulnerabilities(),
                            sbomData.getSbom().getComponents()))
                    .build();

            String reportData = new Gson().toJson(htmlData);
            String htmlJarPath = String.valueOf(new FilePath(new File(HtmlJarHandler.class.getProtectionDomain().getCodeSource().getLocation()
                    .toURI())));

            new HtmlJarHandler(htmlJarPath, reportData).copyHtmlToDir(workspace, build.getId());
            artifactMap.put("index.html", String.format("%s/%s", build.getId(), "index.html"));

            build.getArtifactManager().archive(workspace, launcher, new BuildListenerAdapter(listener), artifactMap);

            listener.getLogger().println("Build Artifacts: " + env.get("RUN_ARTIFACTS_DISPLAY_URL"));

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

    private String getOidcToken(IdTokenStringCredentials oidcStr, IdTokenFileCredentials oidcFile) throws IOException {
        if (oidcStr != null) {
            return oidcStr.getSecret().getPlainText();
        } else if (oidcFile != null) {
            return new String(oidcFile.getContent().readAllBytes(), StandardCharsets.UTF_8);
        }

        return null;
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

        private ListBoxModel getOidcStringIdModels() {
            ListBoxModel items = new ListBoxModel();
            List<IdTokenStringCredentials> credentials = CredentialsProvider.lookupCredentials(
                    IdTokenStringCredentials.class,
                    Jenkins.getInstance(),
                    ACL.SYSTEM,
                    Collections.emptyList()
            );

            for (IdTokenStringCredentials credential : credentials) {
                items.add(credential.getId());
            }

            return items;
        }

        private ListBoxModel getOidcFileIdModels() {
            ListBoxModel items = new ListBoxModel();
            List<IdTokenFileCredentials> credentials = CredentialsProvider.lookupCredentials(
                    IdTokenFileCredentials.class,
                    Jenkins.getInstance(),
                    ACL.SYSTEM,
                    Collections.emptyList()
            );

            for (IdTokenFileCredentials credential : credentials) {
                items.add(credential.getId());
            }

            return items;
        }

        @POST
        @SuppressFBWarnings
        public ListBoxModel doFillOidcCredentialIdItems() {
            if (Jenkins.get().hasPermission(READ)) {
                ListBoxModel items = new ListBoxModel();
                items.add("Select OIDC Credential ID", null);
                items.addAll(getOidcFileIdModels());
                items.addAll(getOidcStringIdModels());
                return items;
            }
            return new ListBoxModel();
        }

        @POST
        public ListBoxModel doFillCredentialIdItems() {
            if (Jenkins.get().hasPermission(READ)) {
                return getCredentialIdModels();
            }
            return new ListBoxModel();
        }

        @SuppressFBWarnings()
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
                if (credential != null && credential.getCredentials() != null) {
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
