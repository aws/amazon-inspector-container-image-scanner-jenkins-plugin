package io.jenkins.plugins.amazoninspectorbuildstep.requests;

import com.amazonaws.auth.AWSSessionCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.auth.STSAssumeRoleSessionCredentialsProvider;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.core.document.Document;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.inspectorscan.InspectorScanClient;
import software.amazon.awssdk.services.inspectorscan.model.ScanSbomRequest;
import software.amazon.awssdk.services.inspectorscan.model.ScanSbomResponse;

import java.net.URI;
import java.net.URISyntaxException;

public class SdkRequests {
    public SdkRequests() {
    }

    public AWSSessionCredentials getCredentialsFromRole(String roleArn, String region) {
        String stsEndpoint = String.format("sts.%s.amazonaws.com",
                region);

        if (region.contains("cn")) {
            stsEndpoint += ".cn";
        }

        AWSSecurityTokenService sts = AWSSecurityTokenServiceClientBuilder.standard()
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration(stsEndpoint, region)).build();

        String ssmSessionName = "AmazonInspectorCICD";

        STSAssumeRoleSessionCredentialsProvider credentialsProvider = new STSAssumeRoleSessionCredentialsProvider
                .Builder(roleArn, ssmSessionName)
                .withStsClient(sts)
                .build();


        return credentialsProvider.getCredentials();
    }

    public String requestSbom(String sbom) throws URISyntaxException {
        AWSSessionCredentials credentials = getCredentialsFromRole("arn:aws:iam::414879708742:role/waltwilo-admin", "us-east-1");
        AwsSessionCredentials.builder().secretAccessKey(credentials.getAWSSecretKey())
                .accessKeyId(credentials.getAWSAccessKeyId())
                .sessionToken(credentials.getSessionToken()).build();
        SdkHttpClient client = ApacheHttpClient.builder().build();
        InspectorScanClient scanClient = InspectorScanClient.builder()
                .region(Region.of("us-east-1"))
                .httpClient(client)
                .endpointOverride(new URI("https://beta.us-east-1.waystar.inspector.aws.a2z.com/scan/sbom"))
                .build();

        ScanSbomRequest request = ScanSbomRequest.builder().sbom(Document.fromString(sbom)).build();
        ScanSbomResponse response = scanClient.scanSbom(request);

        return response.sbom().asString();
    }

    public static void main(String[] args) throws URISyntaxException {
        String sbom = "{ SBOM CONTENT }";
        SdkRequests requests = new SdkRequests();
        requests.requestSbom(sbom);
    }
}
