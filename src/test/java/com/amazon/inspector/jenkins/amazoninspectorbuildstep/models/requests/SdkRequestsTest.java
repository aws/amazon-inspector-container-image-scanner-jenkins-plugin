package com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.requests;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.AmazonInspectorBuilder;
import com.amazonaws.auth.AWSCredentials;
import com.cloudbees.jenkins.plugins.awscredentials.AmazonWebServicesCredentials;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.services.inspectorscan.InspectorScanClient;
import software.amazon.awssdk.services.inspectorscan.model.ScanSbomRequest;
import software.amazon.awssdk.services.inspectorscan.model.ScanSbomResponse;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleWithWebIdentityCredentialsProvider;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SdkRequestsTest {

    @BeforeEach
    void setUp() {
        AmazonInspectorBuilder.setLogger(new PrintStream(new ByteArrayOutputStream()));
    }

    @Test
    void getCredentialProvider_withExplicitCredential_usesStaticProvider() {
        AWSCredentials raw = mock(AWSCredentials.class);
        when(raw.getAWSAccessKeyId()).thenReturn("AKIAEXAMPLE");
        when(raw.getAWSSecretKey()).thenReturn("secretExample");

        AmazonWebServicesCredentials credential = mock(AmazonWebServicesCredentials.class);
        when(credential.getCredentials()).thenReturn(raw);

        SdkRequests sdkRequests = new SdkRequests("us-east-1", credential, null, null, null);

        AwsCredentialsProvider provider =
                sdkRequests.getCredentialProvider(mock(SdkHttpClient.class), null, null, credential);

        assertInstanceOf(StaticCredentialsProvider.class, provider);
    }

    @Test
    void getCredentialProvider_withProfileName_usesProfileProvider() {
        SdkRequests sdkRequests = new SdkRequests("us-east-1", null, null, "my-profile", null);

        AwsCredentialsProvider provider =
                sdkRequests.getCredentialProvider(mock(SdkHttpClient.class), "my-profile", null, null);

        assertInstanceOf(ProfileCredentialsProvider.class, provider);
    }

    @Test
    void getCredentialProvider_withNothingProvided_usesDefaultChain() {
        SdkRequests sdkRequests = new SdkRequests("us-east-1", null, null, null, null);

        AwsCredentialsProvider provider =
                sdkRequests.getCredentialProvider(mock(SdkHttpClient.class), null, null, null);

        assertInstanceOf(DefaultCredentialsProvider.class, provider);
    }

    @Test
    void getCredentialProvider_withRoleArnOnly_usesAssumeRoleProvider() {
        String roleArn = "arn:aws:iam::123456789012:role/inspector";
        SdkRequests sdkRequests = new SdkRequests("us-east-1", null, null, null, roleArn);

        AwsCredentialsProvider provider =
                sdkRequests.getCredentialProvider(mock(SdkHttpClient.class), null, null, null);

        assertInstanceOf(StsAssumeRoleCredentialsProvider.class, provider);
    }

    @Test
    void getCredentialProvider_withRoleArnAndOidc_usesWebIdentityProvider() {
        String roleArn = "arn:aws:iam::123456789012:role/inspector";
        SdkRequests sdkRequests = new SdkRequests("us-east-1", null, "oidc-token", null, roleArn);

        AwsCredentialsProvider provider =
                sdkRequests.getCredentialProvider(mock(SdkHttpClient.class), null, "oidc-token", null);

        assertInstanceOf(StsAssumeRoleWithWebIdentityCredentialsProvider.class, provider);
    }

    @Test
    void getCredentialProvider_emptyProfileName_fallsBackToDefaultChain() {
        SdkRequests sdkRequests = new SdkRequests("us-east-1", null, null, "", null);

        AwsCredentialsProvider provider =
                sdkRequests.getCredentialProvider(mock(SdkHttpClient.class), "", null, null);

        assertInstanceOf(DefaultCredentialsProvider.class, provider);
    }

    @Test
    void requestSbom_onSuccess_returnsSbomAndClosesClients() {
        SdkHttpClient httpClient = mock(SdkHttpClient.class);
        InspectorScanClient scanClient = mock(InspectorScanClient.class);
        ScanSbomResponse response = mock(ScanSbomResponse.class);
        when(response.sbom()).thenReturn(software.amazon.awssdk.core.document.Document.fromString("scanned"));
        when(scanClient.scanSbom(any(ScanSbomRequest.class))).thenReturn(response);

        SdkRequests sdkRequests = spy(new SdkRequests("us-east-1", null, null, null, null));
        doReturn(httpClient).when(sdkRequests).buildHttpClient();
        doReturn(scanClient).when(sdkRequests).buildScanClient(eq(httpClient), any(), any(), any());

        String result = sdkRequests.requestSbom("{\"bomFormat\":\"CycloneDX\"}");

        assertEquals("\"scanned\"", result);
        // Both the shared HTTP client and the per-attempt scan client must be closed.
        verify(httpClient).close();
        verify(scanClient).close();
        // Success on first attempt: only one scan client is built.
        verify(sdkRequests, times(1)).buildScanClient(any(), any(), any(), any());
    }

    @Test
    void requestSbom_firstAttemptFails_retriesOnceThenSucceeds() {
        SdkHttpClient httpClient = mock(SdkHttpClient.class);
        InspectorScanClient failingClient = mock(InspectorScanClient.class);
        InspectorScanClient succeedingClient = mock(InspectorScanClient.class);
        when(failingClient.scanSbom(any(ScanSbomRequest.class)))
                .thenThrow(new RuntimeException("auth failure"));
        ScanSbomResponse response = mock(ScanSbomResponse.class);
        when(response.sbom()).thenReturn(software.amazon.awssdk.core.document.Document.fromString("recovered"));
        when(succeedingClient.scanSbom(any(ScanSbomRequest.class))).thenReturn(response);

        SdkRequests sdkRequests = spy(new SdkRequests("us-east-1", null, null, "explicit-profile", null));
        doReturn(httpClient).when(sdkRequests).buildHttpClient();
        doReturn(failingClient).doReturn(succeedingClient)
                .when(sdkRequests).buildScanClient(eq(httpClient), any(), any(), any());

        String result = sdkRequests.requestSbom("{\"bomFormat\":\"CycloneDX\"}");

        assertEquals("\"recovered\"", result);
        // Two attempts: the failing client and the recovering client are both built and closed.
        verify(sdkRequests, times(2)).buildScanClient(any(), any(), any(), any());
        verify(failingClient).close();
        verify(succeedingClient).close();
        verify(httpClient).close();
    }

    @Test
    void requestSbom_bothAttemptsFail_rethrowsAndClosesClients() {
        SdkHttpClient httpClient = mock(SdkHttpClient.class);
        InspectorScanClient scanClient = mock(InspectorScanClient.class);
        when(scanClient.scanSbom(any(ScanSbomRequest.class)))
                .thenThrow(new RuntimeException("persistent failure"));

        SdkRequests sdkRequests = spy(new SdkRequests("us-east-1", null, null, null, null));
        doReturn(httpClient).when(sdkRequests).buildHttpClient();
        doReturn(scanClient).when(sdkRequests).buildScanClient(eq(httpClient), any(), any(), any());

        assertThrows(RuntimeException.class,
                () -> sdkRequests.requestSbom("{\"bomFormat\":\"CycloneDX\"}"));

        // One retry then give up: exactly two attempts, all clients closed even on failure.
        verify(sdkRequests, times(2)).buildScanClient(any(), any(), any(), any());
        verify(scanClient, times(2)).close();
        verify(httpClient).close();
    }
}
