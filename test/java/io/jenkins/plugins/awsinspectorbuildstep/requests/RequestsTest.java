package io.jenkins.plugins.awsinspectorbuildstep.requests;

import com.google.common.io.CharStreams;
import jline.internal.InputStreamReader;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;

import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class RequestsTest {
    Requests requests;
    AwsBasicCredentials credentials;
    @Before
    public void setUp() {
        credentials = AwsBasicCredentials.create("test", "test");
        String sessionToken = "test";
        String filePath =
                "/Users/waltwilo/workplace/EeveeCICDPlugin/src/EeveeCICDJenkinsPlugin/test/data/bomermanOutput.json";

        requests = Mockito.spy(new Requests(credentials, sessionToken, filePath, new PrintStream(System.out)));
    }

    @Test
    public void testSignRequest_Success() {
        SdkHttpFullRequest request = SdkHttpFullRequest.builder()
                .method(SdkHttpMethod.POST)
                .uri(URI.create("https://test.com/api"))
                .putHeader("X-Amz-Security-Token", "test")
                .putHeader("X-Amz-Date", "20230804T172718Z")
                .build();

        String authPrefix = "[AWS4-HMAC-SHA256 Credential=test/20230804/us-east-1/test/aws4_request, " +
                "SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=";
        assertTrue(requests.signRequest("test", request).headers().get("Authorization").toString()
                .startsWith(authPrefix));
    }

    @Test
    public void testBuildRequest_Success() throws IOException {
        String date = "20230804T172718Z";
        SdkHttpFullRequest request = requests.buildRequest(URI.create("https://www.endpoint.com/path/"), date);
        assertEquals(request.headers().get("X-Amz-Date"), List.of(date));
        assertEquals(request.headers().get("X-Amz-Security-Token"), List.of("test"));
        assertEquals(request.host(), "www.endpoint.com");
        assertEquals(request.encodedPath(), "/path/");
        assertEquals(request.method(), SdkHttpMethod.POST);

        List<String> requestBody = CharStreams.readLines(
                new InputStreamReader(request.contentStreamProvider().get().newStream()));
        assertEquals(requestBody.size(), 358);
    }

    @Test
    public void testGetXAmzDateString() {
        String testDate = "2023-08-04T18:56:53.531004Z";
        Assert.assertEquals(requests.getXAmzDateString(testDate), "20230804T185653Z");
    }
}
