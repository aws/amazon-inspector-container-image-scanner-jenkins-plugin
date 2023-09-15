package io.jenkins.plugins.amazoninspectorbuildstep.requests;

import io.jenkins.plugins.amazoninspectorbuildstep.exception.RetriesExceededLimitException;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.http.AbortableInputStream;
import software.amazon.awssdk.http.ExecutableHttpRequest;
import software.amazon.awssdk.http.HttpExecuteResponse;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpResponse;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;

public class RequestsTest {
    Requests requests;
    @Before
    public void setUp() {
        AwsBasicCredentials credentials = AwsBasicCredentials.create("test", "test");
        String sessionToken = "test";
        String filePath =
                "/Users/waltwilo/workplace/EeveeCICDPlugin/src/EeveeCICDJenkinsPlugin/test/data/bomermanOutput.json";

        requests = Mockito.spy(new Requests(credentials, sessionToken, filePath, new PrintStream(System.out), ""));
    }

    @Test
    public void testHandleResponse_SuccessResponse() throws IOException, InterruptedException, RetriesExceededLimitException {
        SdkHttpFullRequest mockRequest = Mockito.mock(SdkHttpFullRequest.class);
        ExecutableHttpRequest mockExecutableRequest = Mockito.mock(ExecutableHttpRequest.class);
        SdkHttpClient mockClient = Mockito.mock(SdkHttpClient.class);

        HttpExecuteResponse testResponse = HttpExecuteResponse.builder()
                .responseBody(AbortableInputStream.create(new ByteArrayInputStream("Test".getBytes(StandardCharsets.UTF_8))))
                .response(SdkHttpResponse.builder()
                        .statusCode(200)
                        .build()
                ).build();

        Mockito.doReturn(mockExecutableRequest).when(mockClient).prepareRequest(any());
        Mockito.doReturn(testResponse).when(mockExecutableRequest).call();
        RetryWaitHandler retryWaitHandler = new RetryWaitHandler(System.out, 1000, 3, 1000);

//        assertEquals(requests.handleRequest(mockClient, mockRequest, retryWaitHandler).length(), 4);
    }

    @Test
    public void testHandleResponse_NonSuccessResponse() throws IOException, RetriesExceededLimitException, InterruptedException {
        SdkHttpFullRequest mockRequest = Mockito.mock(SdkHttpFullRequest.class);
        ExecutableHttpRequest mockExecutableRequest = Mockito.mock(ExecutableHttpRequest.class);
        SdkHttpClient mockClient = Mockito.mock(SdkHttpClient.class);

        HttpExecuteResponse testResponse = HttpExecuteResponse.builder()
                .responseBody(AbortableInputStream.create(new ByteArrayInputStream("Test".getBytes(StandardCharsets.UTF_8))))
                .response(SdkHttpResponse.builder()
                        .statusCode(500)
                        .build()
                ).build();

        Mockito.doReturn(mockExecutableRequest).when(mockClient).prepareRequest(any());
        Mockito.doReturn(testResponse).when(mockExecutableRequest).call();

        RetryWaitHandler retryWaitHandler = new RetryWaitHandler(System.out, 30000, 3, 120000);

//        assertThrows(RetriesExceededLimitException.class, () -> requests.handleRequest(mockClient, mockRequest,
//                retryWaitHandler));
    }
}
