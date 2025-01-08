package com.amazon.inspector.jenkins.amazoninspectorbuildstep;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.requests.SdkRequests;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Sbom;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Vulnerability;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomgen.SbomgenDownloader;
import com.cloudbees.jenkins.plugins.awscredentials.AmazonWebServicesCredentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
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
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
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
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.SbomData;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomparsing.SbomOutputParser;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.sbomparsing.Severity;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.html.HtmlConversionUtils;
import io.jenkins.plugins.oidc_provider.IdTokenFileCredentials;
import io.jenkins.plugins.oidc_provider.IdTokenStringCredentials;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import jenkins.util.BuildListenerAdapter;
import lombok.Getter;
import net.sf.json.JSONObject;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.verb.POST;
import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils.InspectorRegions.INSPECTOR_REGIONS;
import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils.Sanitizer.sanitizeFilePath;
import static com.amazon.inspector.jenkins.amazoninspectorbuildstep.utils.Sanitizer.sanitizeUrl;
import static hudson.security.Permission.READ;

@Getter
public class AmazonInspectorBuilder extends Builder implements SimpleBuildStep {
    @SuppressFBWarnings()
    public static PrintStream logger;
    private final String archivePath;
    private final String archiveType;
    private final String iamRole;
    private final String awsRegion;
    private final String credentialId;
    private final String oidcCredentialId;
    private final boolean isThresholdEnabled;
    private final boolean thresholdEquals;
    private final boolean osArch;
    private final int countCritical;
    private final int countHigh;
    private final int countMedium;
    private final int countLow;
    private final String awsCredentialId;
    private final String awsProfileName;
    private final String sbomgenSelection;
    private final String sbomgenPath;
    private final String sbomgenSkipFiles;
    private final Double epssThreshold;
    private Job<?, ?> job;

    @DataBoundConstructor
    public AmazonInspectorBuilder(String archivePath, String artifactPath, String archiveType, boolean osArch, String iamRole,
                                  String awsRegion, String credentialId, String awsProfileName, String awsCredentialId,
                                  String sbomgenSelection, String sbomgenPath, boolean isThresholdEnabled, boolean thresholdEquals,
                                  int countCritical, int countHigh, int countMedium, int countLow, String oidcCredentialId, String sbomgenSkipFiles, Double epssThreshold) {
        if (artifactPath != null && !artifactPath.isEmpty()) {
            this.archivePath = artifactPath;
        } else {
            this.archivePath = archivePath;
        }
        this.archiveType = archiveType;
        this.credentialId = credentialId;
        this.awsCredentialId = awsCredentialId;
        this.oidcCredentialId = oidcCredentialId;
        this.awsProfileName = awsProfileName;
        this.osArch = osArch;
        this.iamRole = iamRole;
        this.awsRegion = awsRegion;
        this.sbomgenSelection = (sbomgenSelection != null) ? sbomgenSelection : "automatic";
        this.sbomgenPath = sbomgenPath;
        this.sbomgenSkipFiles = sbomgenSkipFiles;
        this.isThresholdEnabled = isThresholdEnabled;
        this.thresholdEquals = thresholdEquals;
        this.countCritical = countCritical;
        this.countHigh = countHigh;
        this.countMedium = countMedium;
        this.countLow = countLow;
        this.epssThreshold = epssThreshold;
    }

    private boolean doesBuildFail(Map<Severity, Integer> counts) {
        boolean criticalExceedsLimit = counts.get(Severity.CRITICAL) > countCritical;
        boolean highExceedsLimit = counts.get(Severity.HIGH) > countHigh;
        boolean mediumExceedsLimit = counts.get(Severity.MEDIUM) > countMedium;
        boolean lowExceedsLimit = counts.get(Severity.LOW) > countLow;

        boolean criticalEqualsLimit = counts.get(Severity.CRITICAL) == countCritical;
        boolean highEqualsLimit = counts.get(Severity.HIGH) == countHigh;
        boolean mediumEqualsLimit = counts.get(Severity.MEDIUM) == countMedium;
        boolean lowEqualsLimit = counts.get(Severity.LOW) == countLow;

        if (this.thresholdEquals) {
            logger.println("Threshold should equal vulnerabilites, regression testing.");
            return !(criticalEqualsLimit && highEqualsLimit && mediumEqualsLimit && lowEqualsLimit);
        }
        return criticalExceedsLimit || highExceedsLimit || mediumExceedsLimit || lowExceedsLimit;
    }


    @Override
    public void perform(Run<?, ?> build, FilePath workspace, EnvVars env, Launcher launcher, TaskListener listener)
            throws IOException, InterruptedException {
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

            String sbomgenSelection = this.sbomgenSelection;

            String activeSbomgenPath;
            if ("automatic".equalsIgnoreCase(sbomgenSelection)) {
                logger.println("Automatic SBOMGen selected, downloading using default settings...");
                activeSbomgenPath = SbomgenDownloader.getBinary(workspace);
            } else if ("manual".equalsIgnoreCase(sbomgenSelection)) {
                if (sbomgenPath == null || sbomgenPath.isEmpty()) {
                    throw new IllegalArgumentException("Manual SBOMGen selected but no path provided.");
                }
                File sbomgenFile = new File(sbomgenPath);
                if (!sbomgenFile.exists() || !sbomgenFile.canExecute()) {
                    throw new IllegalArgumentException("Provided SBOMgen path is invalid or not executable: " + sbomgenPath);
                }
                logger.println("Manual SBOMGen selected, using provided path: " + sbomgenPath);
                activeSbomgenPath = sbomgenPath;
            } else {
                logger.println("Invalid SBOMGen selection. Defaulting to Automatic.");
                activeSbomgenPath = SbomgenDownloader.getBinary(workspace);
            }

            StandardUsernamePasswordCredentials credential = null;
            if (credentialId == null) {
                logger.println("Credential ID is null, this is not normal, please check your config. " +
                        "Continuing without docker credentials.");
            } else {
                credential = CredentialsProvider.findCredentialById(credentialId,
                        StandardUsernamePasswordCredentials.class, build);
            }
            String skipfiles = (sbomgenSkipFiles != null) ? sbomgenSkipFiles : "";
            String sbom;
            if (credential != null) {
                sbom = new SbomgenRunner(launcher, activeSbomgenPath, activeArchiveType, archivePath, credential.getUsername(),
                        credential.getPassword().getPlainText(),skipfiles).run();
            } else {
                sbom = new SbomgenRunner(launcher, activeSbomgenPath, activeArchiveType, archivePath, null, null, skipfiles).run();
            }

            JsonElement metadata = JsonParser.parseString(sbom).getAsJsonObject().get("metadata");
            JsonObject component = null;
            if (metadata != null && metadata.getAsJsonObject().get("component") != null) {
                component = metadata.getAsJsonObject().get("component").getAsJsonObject();
            }

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
            String csvVulnFileName = String.format("%s-%s-vuln.csv", build.getParent().getDisplayName(),
                    build.getDisplayName()).replaceAll("[ #]", "");
            String csvVulnWorkspacePath = String.format("%s/%s", build.getId(), csvVulnFileName);

            FilePath csvVulnFile = workspace.child(csvVulnWorkspacePath);

            String csvDockerFileName = String.format("%s-%s-docker.csv", build.getParent().getDisplayName(),
                    build.getDisplayName()).replaceAll("[ #]", "");
            String csvDockerWorkspacePath = String.format("%s/%s", build.getId(), csvDockerFileName);
            FilePath csvDockerFile = workspace.child(csvDockerWorkspacePath);
            logger.println("Converting SBOM Results to CSV.");

            SbomOutputParser parser = new SbomOutputParser(sbomData);
            parser.parseVulnCounts();

            String sanitizedArchiveName = null;
            String componentName = null;
            if (component != null && component.get("name") != null) {
                componentName = component.get("name").getAsString();
            }

            if (componentName != null && componentName.endsWith(".tar")) {
                sanitizedArchiveName = sanitizeFilePath("file://" + componentName);
            } else {
                sanitizedArchiveName = archivePath;
            }

            converter.routeVulnerabilities();
            String csvVulnContent = converter.convertVulnerabilities(sanitizedArchiveName, imageSha, build.getId(), SbomOutputParser.vulnCounts);
            if (csvVulnContent != null) {
                artifactMap.put(csvVulnFileName, csvVulnWorkspacePath);
                csvVulnFile.write(csvVulnContent, "UTF-8");
            }

            String csvDockerContent = converter.convertDocker(sanitizedArchiveName, imageSha, build.getId(), SbomOutputParser.dockerCounts);
            if (csvDockerContent != null) {
                artifactMap.put(csvDockerFileName, csvDockerWorkspacePath);
                csvDockerFile.write(csvDockerContent, "UTF-8");
            }

            String[] splitName = sanitizedArchiveName.split(":");
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
                    .docker(HtmlConversionUtils.convertDocker(sbomData.getSbom().getVulnerabilities(),
                            sbomData.getSbom().getComponents()))
                    .vulnerabilities(HtmlConversionUtils.convertVulnerabilities(sbomData.getSbom().getVulnerabilities(),
                            sbomData.getSbom().getComponents()))
                    .build();

            String reportData = gson.toJson(htmlData);

            String htmlJarPath = String.valueOf(new FilePath(new File(HtmlJarHandler.class.getProtectionDomain().getCodeSource().getLocation()
                    .toURI())));

            new HtmlJarHandler(htmlJarPath, reportData).copyHtmlToDir(workspace, build.getId());
            artifactMap.put("index.html", String.format("%s/%s", build.getId(), "index.html"));

            build.getArtifactManager().archive(workspace, launcher, new BuildListenerAdapter(listener), artifactMap);

            listener.getLogger().println("Build Artifacts: " + env.get("RUN_ARTIFACTS_DISPLAY_URL"));

            boolean doesBuildPass = !doesBuildFail(SbomOutputParser.aggregateCounts.getCounts());

            if (!isThresholdEnabled) {
                listener.getLogger().println("Thresholds disabled. Skipping all threshold/EPSS checks.");
            } else {
                if (epssThreshold != null) {
                    listener.getLogger().println("EPSS Threshold set to: " + epssThreshold);
                    boolean cvesExceedThreshold = assessCVEsAgainstEPSS(build, workspace, listener, epssThreshold, sbomWorkspacePath);
                    if (cvesExceedThreshold) {
                        build.setResult(Result.FAILURE);
                        return;
                    } else {
                        listener.getLogger().println("All CVEs are within the EPSS threshold of " + epssThreshold + ".");
                    }
                } else {
                    listener.getLogger().println("No EPSS Threshold specified. Skipping EPSS assessment.");
                }
            }

            if (!isThresholdEnabled) {
                build.setResult(Result.SUCCESS);
                doesBuildPass = true;
            } else if (isThresholdEnabled && doesBuildPass) {
                build.setResult(Result.SUCCESS);
            } else {
                build.setResult(Result.FAILURE);
            }

            listener.getLogger().println("Results: " + SbomOutputParser.aggregateCounts.toString());
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

    private boolean assessCVEsAgainstEPSS(Run<?, ?> build, FilePath workspace, TaskListener listener, Double epssThreshold, String sbomPath)
            throws IOException, InterruptedException {
        FilePath sbomFile = workspace.child(sbomPath);
        if (!sbomFile.exists()) {
            listener.getLogger().println("SBOM file not found at: " + sbomFile.getRemote());
            return true;
        }
        try {
            String sbomContent = sbomFile.readToString();
            listener.getLogger().println("SBOM file read successfully.");
            Gson gson = new Gson();
            Sbom sbom = gson.fromJson(sbomContent, Sbom.class);
            listener.getLogger().println("SBOM JSON parsed successfully.");
            List<Vulnerability> vulnerabilities = sbom.getVulnerabilities();
            if (vulnerabilities == null || vulnerabilities.isEmpty()) {
                listener.getLogger().println("No vulnerabilities found in the SBOM.");
                return false;
            }
            listener.getLogger().println("Starting EPSS assessment for vulnerabilities...");
            boolean exceedsThreshold = false;
            Map<String, Double> exceedingCVEsMap = new HashMap<>();
            for (Vulnerability vulnerability : vulnerabilities) {
                String cveId = vulnerability.getId();
                Double epssScore = vulnerability.getEpssScore();
                if (epssScore == null) {
                    continue;
                }
                if (epssScore >= epssThreshold) {
                    exceedsThreshold = true;
                    exceedingCVEsMap.put(cveId, epssScore);
                }
            }
            if (exceedsThreshold) {
                listener.getLogger().println("The following CVEs exceed the EPSS threshold of " + epssThreshold + ":");
                for (Map.Entry<String, Double> entry : exceedingCVEsMap.entrySet()) {
                    listener.getLogger().println(String.format("CVE: %s, EPSS Score: %.4f", entry.getKey(), entry.getValue()));
                }
                listener.getLogger().println("Failing the build due to EPSS threshold breach.");
            } else {
                listener.getLogger().println("All assessed CVEs are within the EPSS threshold of " + epssThreshold + ".");
            }
            return exceedsThreshold;
        } catch (JsonParseException e) {
            listener.getLogger().println("Invalid JSON structure in SBOM file: " + e.getMessage());
            return true;
        } catch (IOException e) {
            listener.getLogger().println("Error reading SBOM file: " + e.getMessage());
            return true;
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
        try {
            JsonElement jsonElement = JsonParser.parseString(sbom);
            JsonObject metadata = jsonElement.getAsJsonObject().get("metadata").getAsJsonObject();
            JsonObject component = metadata.get("component").getAsJsonObject();
            JsonArray properties = component.getAsJsonObject().get("properties").getAsJsonArray();

            for (JsonElement property : properties) {
                if (property.getAsJsonObject().get("name").getAsString().contains("image_id")) {
                    return property.getAsJsonObject().get("value").getAsString();
                }
            }
        } catch (Exception e) {
            AmazonInspectorBuilder.logger.println("An exception occurred when getting image sha.");
            AmazonInspectorBuilder.logger.println(e);
        }

        return "N/A";
    }


    @Symbol("Amazon Inspector")
    @Extension
    public static class DescriptorImpl extends BuildStepDescriptor<Builder> {
        public DescriptorImpl() {
            load();
        }

        @Override
        public AmazonInspectorBuilder newInstance(StaplerRequest req, JSONObject formData) throws FormException {
            JSONObject selectionObj = formData.optJSONObject("sbomgenSelection");
            String sbomValue = "automatic";
            if (selectionObj != null && selectionObj.has("value")) {
                sbomValue = selectionObj.getString("value");
            }
            if ("manual".equalsIgnoreCase(sbomValue)) {
                String sbomgenPath = selectionObj.optString("sbomgenPath", "").trim();
                formData.put("sbomgenPath", sbomgenPath);
            } else {
                formData.put("sbomgenPath", "");
            }
            formData.put("sbomgenSelection", sbomValue);

            boolean thresholdEnabled = formData.optBoolean("isThresholdEnabled", false);
            formData.put("isThresholdEnabled", thresholdEnabled);

            boolean thresholdEquals = formData.optBoolean("thresholdEquals", false);
            formData.put("thresholdEquals", thresholdEquals);

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

        @POST
        public FormValidation doCheckEpssThreshold(@QueryParameter String value) {
            Jenkins.get().checkPermission(Job.CONFIGURE);
            if (value == null || value.trim().isEmpty()) {
                return FormValidation.ok();
            }
            try {
                double d = Double.parseDouble(value);
                if (d < 0.0 || d > 1.0) {
                    return FormValidation.error("EPSS threshold must be between 0.0 and 1.0.");
                }
            } catch (NumberFormatException e) {
                return FormValidation.error("EPSS threshold must be a numeric value between 0.0 and 1.0.");
            }
            return FormValidation.ok();
        }

        @POST
        public FormValidation doCheckCountCritical(@QueryParameter String value) {
            Jenkins.get().checkPermission(Job.CONFIGURE);
            return validateNumericThreshold(value, "Critical");
        }
        @POST
        public FormValidation doCheckCountHigh(@QueryParameter String value) {
            Jenkins.get().checkPermission(Job.CONFIGURE);
            return validateNumericThreshold(value, "High");
        }
        @POST
        public FormValidation doCheckCountMedium(@QueryParameter String value) {
            Jenkins.get().checkPermission(Job.CONFIGURE);
            return validateNumericThreshold(value, "Medium");
        }
        @POST
        public FormValidation doCheckCountLow(@QueryParameter String value) {
            Jenkins.get().checkPermission(Job.CONFIGURE);
            return validateNumericThreshold(value, "Low");
        }

        private FormValidation validateNumericThreshold(String value, String fieldName) {
            Jenkins.get().checkPermission(Job.CONFIGURE);
            if (value == null || value.trim().isEmpty()) {
                return FormValidation.error(fieldName + " threshold cannot be empty.");
            }
            try {
                int intValue = Integer.parseInt(value);
                if (intValue < 0) {
                    return FormValidation.error(fieldName + " threshold must be a non-negative integer.");
                }
            } catch (NumberFormatException e) {
                return FormValidation.error(fieldName + " threshold must be a numeric value.");
            }
            return FormValidation.ok();
        }

        @POST
        public FormValidation doCheckArchivePath(@QueryParameter String value) {
            Jenkins.get().checkPermission(Job.CONFIGURE);
            if (value == null || value.trim().isEmpty()) {
                return FormValidation.error("Image Id is required. Provide a valid local/remote image name or path to an image tar file.");
            }
            if (!value.contains(":") && !value.contains("@") && !value.endsWith(".tar")) {
                return FormValidation.warning("This doesn't look like a standard Docker image name or a tar file path. Verify it matches the expected format.");
            }
            return FormValidation.ok();
        }

        @POST
        public FormValidation doCheckAwsRegion(@QueryParameter String value) {
            Jenkins.get().checkPermission(Job.CONFIGURE);
            if (value == null || value.trim().isEmpty()) {
                return FormValidation.error("You must select an AWS Region.");
            }
            if ("Select AWS Region".equals(value)) {
                return FormValidation.error("Please select a AWS Region from the list.");
            }
            boolean isValid = false;
            for (String region : INSPECTOR_REGIONS) {
                if (region.equals(value)) {
                    isValid = true;
                    break;
                }
            }
            if (!isValid) {
                return FormValidation.error("Please pick one from the list.");
            }
            return FormValidation.ok();
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
