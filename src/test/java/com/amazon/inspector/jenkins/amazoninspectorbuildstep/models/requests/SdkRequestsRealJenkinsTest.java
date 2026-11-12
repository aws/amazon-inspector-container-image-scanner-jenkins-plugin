package com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.requests;

import com.cloudbees.jenkins.plugins.awscredentials.AmazonWebServicesCredentials;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.RealJenkinsExtension;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.services.inspectorscan.InspectorScanClient;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class SdkRequestsRealJenkinsTest {

    @RegisterExtension
    private final RealJenkinsExtension extension = new RealJenkinsExtension();

    @Test
    void buildsClientsAgainstSdkCorePlugin() throws Throwable {
        extension.then(SdkRequestsRealJenkinsTest::buildClients);
    }

    private static void buildClients(JenkinsRule r) throws Throwable {
        buildScanClient(new SdkRequests("us-east-1", null, null, null, null));
        buildScanClient(new SdkRequests("us-east-1", null, null, null, "arn:aws:iam::123456789012:role/example"));
    }

    private static void buildScanClient(SdkRequests sdkRequests) throws Throwable {
        Method buildHttpClient = SdkRequests.class.getDeclaredMethod("buildHttpClient");
        Method buildScanClient = SdkRequests.class.getDeclaredMethod("buildScanClient",
                SdkHttpClient.class, String.class, String.class, AmazonWebServicesCredentials.class);
        buildHttpClient.setAccessible(true);
        buildScanClient.setAccessible(true);

        try (SdkHttpClient httpClient = (SdkHttpClient) buildHttpClient.invoke(sdkRequests);
             InspectorScanClient scanClient =
                     (InspectorScanClient) buildScanClient.invoke(sdkRequests, httpClient, null, null, null)) {
            assertNotNull(scanClient);
        }
    }
}
