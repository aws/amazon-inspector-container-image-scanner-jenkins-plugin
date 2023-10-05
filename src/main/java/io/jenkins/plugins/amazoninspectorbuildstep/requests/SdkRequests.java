package io.jenkins.plugins.amazoninspectorbuildstep.requests;

import lombok.AllArgsConstructor;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.protocols.json.internal.unmarshall.document.DocumentUnmarshaller;
import software.amazon.awssdk.protocols.jsoncore.JsonNodeParser;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.inspectorscan.InspectorScanClient;
import software.amazon.awssdk.services.inspectorscan.model.ScanSbomRequest;
import software.amazon.awssdk.services.inspectorscan.model.ScanSbomResponse;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.core.document.Document;

import java.net.URI;
import java.net.URISyntaxException;

@AllArgsConstructor
public class SdkRequests {
    String region;
    String roleArn;

    public Document requestSbom(String sbom) throws URISyntaxException {
        System.out.println(sbom);
        SdkHttpClient client = ApacheHttpClient.builder().build();
        InspectorScanClient scanClient = InspectorScanClient.builder()
                .region(Region.of(region))
                .httpClient(client)
                .credentialsProvider(getCredentialProvider())
                .endpointOverride(new URI(String.format("https://prod.%s.waystar.inspector.aws.a2z.com", region)))
                .build();

        JsonNodeParser jsonNodeParser = JsonNodeParser.create();
        DocumentUnmarshaller unmarshaller = new DocumentUnmarshaller();
        Document document = jsonNodeParser.parse(sbom).visit(unmarshaller);

        ScanSbomRequest request = ScanSbomRequest.builder().sbom(document).build();
        ScanSbomResponse response = scanClient.scanSbom(request);

        return response.sbom();
    }

    public StsAssumeRoleCredentialsProvider getCredentialProvider() {
        StsClient stsClient = StsClient.builder()
                .region(Region.of(region))
                .build();

        return StsAssumeRoleCredentialsProvider.builder().stsClient(stsClient).refreshRequest(AssumeRoleRequest.builder()
                .roleArn(roleArn)
                .roleSessionName("inspectorscan").build()).build();
    }
}
