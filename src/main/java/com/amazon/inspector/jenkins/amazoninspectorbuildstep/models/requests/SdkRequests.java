package com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.requests;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.AmazonInspectorBuilder;
import com.cloudbees.jenkins.plugins.awscredentials.AmazonWebServicesCredentials;
import com.google.common.annotations.VisibleForTesting;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.document.Document;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.protocols.json.internal.unmarshall.document.DocumentUnmarshaller;
import software.amazon.awssdk.protocols.jsoncore.JsonNodeParser;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.inspectorscan.InspectorScanClient;
import software.amazon.awssdk.services.inspectorscan.model.OutputFormat;
import software.amazon.awssdk.services.inspectorscan.model.ScanSbomRequest;
import software.amazon.awssdk.services.inspectorscan.model.ScanSbomResponse;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleWithWebIdentityCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleWithWebIdentityRequest;

public class SdkRequests {
    private final String region;
    private final AmazonWebServicesCredentials awsCredential;
    private final String oidc;
    private final String roleArn;
    private final String awsProfileName;

    public SdkRequests(String region, AmazonWebServicesCredentials awsCredential, String oidc,
                       String awsProfileName, String roleArn) {
        this.region = region;
        this.awsCredential = awsCredential;
        this.awsProfileName = awsProfileName;
        this.roleArn = roleArn;
        this.oidc = oidc;
    }

    public String requestSbom(String sbom) {
        String workingProfileName = awsProfileName;
        AmazonWebServicesCredentials workingCredential = awsCredential;
        String workingOidc = oidc;
        boolean retry = true;

        try (SdkHttpClient client = buildHttpClient()) {
            while (true) {
                try (InspectorScanClient scanClient =
                             buildScanClient(client, workingProfileName, workingOidc, workingCredential)) {

                    JsonNodeParser jsonNodeParser = JsonNodeParser.create();
                    DocumentUnmarshaller unmarshaller = new DocumentUnmarshaller();
                    Document document = jsonNodeParser.parse(sbom).visit(unmarshaller);

                    ScanSbomRequest request = ScanSbomRequest.builder()
                            .sbom(document)
                            .outputFormat(OutputFormat.CYCLONE_DX_1_5)
                            .build();
                    ScanSbomResponse response = scanClient.scanSbom(request);
                    return response.sbom().toString();
                } catch (Exception e) {
                    e.printStackTrace(AmazonInspectorBuilder.getLogger());
                    if (!retry) {
                        throw e;
                    }

                    retry = false;
                    AmazonInspectorBuilder.getLogger().println("An issue occurred while authenticating, attempting to " +
                            "authenticate with default credential provider chain");
                    workingProfileName = "default";
                    workingCredential = null;
                    workingOidc = null;
                }
            }
        }
    }

    @VisibleForTesting
    SdkHttpClient buildHttpClient() {
        return ApacheHttpClient.builder().build();
    }

    @VisibleForTesting
    InspectorScanClient buildScanClient(SdkHttpClient client, String workingProfileName, String workingOidc,
                                        AmazonWebServicesCredentials workingCredential) {
        return InspectorScanClient.builder()
                .region(Region.of(region))
                .httpClient(client)
                .credentialsProvider(getCredentialProvider(client, workingProfileName, workingOidc, workingCredential))
                .overrideConfiguration(ClientOverrideConfiguration.builder()
                        .putHeader("Accept-Encoding", "gzip")
                        .build())
                .build();
    }

    @VisibleForTesting
    AwsCredentialsProvider getCredentialProvider(SdkHttpClient client, String workingProfileName, String workingOidc,
                                                 AmazonWebServicesCredentials workingCredential) {
        if (workingCredential != null) {
            AmazonInspectorBuilder.getLogger().println("Using explicitly provided AWS credentials to authenticate.");
            return StaticCredentialsProvider.create(
                    createRawCredentialProvider(workingCredential).resolveCredentials());
        } else if (roleArn != null && !roleArn.isEmpty() && workingOidc != null && !workingOidc.isEmpty()) {
            AmazonInspectorBuilder.getLogger().println("Using OAuth token and role to authenticate.");
            // No credentials provider needed: AssumeRoleWithWebIdentity is an unsigned STS call.
            StsClient stsClient = StsClient.builder()
                    .region(Region.of(region))
                    .httpClient(client)
                    .build();
            AssumeRoleWithWebIdentityRequest webIdentityRequest = AssumeRoleWithWebIdentityRequest.builder()
                    .roleArn(roleArn)
                    .roleSessionName("inspectorscan")
                    .webIdentityToken(workingOidc)
                    .build();
            return StsAssumeRoleWithWebIdentityCredentialsProvider.builder()
                    .stsClient(stsClient)
                    .refreshRequest(webIdentityRequest)
                    .build();
        } else if (roleArn != null && !roleArn.isEmpty()) {
            AmazonInspectorBuilder.getLogger().println("Authenticating to STS via a role and default credential provider chain.");
            StsClient stsClient = StsClient.builder()
                    .region(Region.of(region))
                    .httpClient(client)
                    .build();
            return StsAssumeRoleCredentialsProvider.builder()
                    .stsClient(stsClient)
                    .refreshRequest(AssumeRoleRequest.builder()
                            .roleArn(roleArn)
                            .roleSessionName("inspectorscan")
                            .build())
                    .build();
        } else if (workingProfileName != null && !workingProfileName.isEmpty()) {
            AmazonInspectorBuilder.getLogger().println(
                    String.format("AWS Credential and role not provided, authenticating using \"%s\" as profile name.",
                            workingProfileName)
            );
            return ProfileCredentialsProvider.builder().profileName(workingProfileName).build();
        } else {
            AmazonInspectorBuilder.getLogger().println("Using default credential provider chain to authenticate.");
            return DefaultCredentialsProvider.create();
        }
    }

    private AwsCredentialsProvider createRawCredentialProvider(AmazonWebServicesCredentials workingCredential) {
        return () -> new AwsCredentials() {
            @Override
            public String accessKeyId() {
                return workingCredential.getCredentials().getAWSAccessKeyId();
            }

            @Override
            public String secretAccessKey() {
                return workingCredential.getCredentials().getAWSSecretKey();
            }
        };
    }
}
