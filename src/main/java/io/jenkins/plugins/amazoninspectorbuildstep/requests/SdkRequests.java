package io.jenkins.plugins.amazoninspectorbuildstep.requests;

import com.amazonaws.auth.AWSSessionCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.auth.STSAssumeRoleSessionCredentialsProvider;
import com.amazonaws.client.builder.AwsClientBuilder;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.core.document.Document;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.inspectorscan.InspectorScanClient;
import software.amazon.awssdk.services.inspectorscan.model.ScanSbomRequest;
import software.amazon.awssdk.services.inspectorscan.model.ScanSbomResponse;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.StsClientBuilder;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;

import java.net.URI;
import java.net.URISyntaxException;

public class SdkRequests {
    public SdkRequests() {
    }

    public String requestSbom(String sbom) throws URISyntaxException {

        SdkHttpClient client = ApacheHttpClient.builder().build();
        InspectorScanClient scanClient = InspectorScanClient.builder()
                .region(Region.of("us-east-1"))
                .httpClient(client)
                .credentialsProvider(getCredentialProvider())
                .endpointOverride(new URI("https://beta.us-east-1.waystar.inspector.aws.a2z.com"))
                .build();

        ScanSbomRequest request = ScanSbomRequest.builder().sbom(Document.fromString(sbom)).build();
        ScanSbomResponse response = scanClient.scanSbom(request);

        return response.sbom().asString();
    }

    public StsAssumeRoleCredentialsProvider getCredentialProvider() {
        StsClient stsClient = StsClient.builder()
                .region(Region.of("us-east-1"))
                .credentialsProvider(ProfileCredentialsProvider.create())
                .build();


        return StsAssumeRoleCredentialsProvider.builder().stsClient(stsClient).refreshRequest(AssumeRoleRequest.builder()
                .roleArn("arn:aws:iam::414879708742:role/waltwilo-admin")
                .roleSessionName("test").build()).build();
    }

    public static void main(String[] args) throws URISyntaxException {

        String sbom = "{ SBOM CONTENT }";
        SdkRequests requests = new SdkRequests();
        requests.requestSbom(sbom);
    }
}
