package io.jenkins.plugins.awsinspectorbuildstep.requests;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.http.AbortableInputStream;
import software.amazon.awssdk.http.HttpExecuteResponse;
import software.amazon.awssdk.http.SdkHttpResponse;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintStream;

import static org.junit.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
    public void testHandleResponse_SuccessResponse() throws IOException {
        final String filePath = "test/data/SbomOutputExample.json";
        HttpExecuteResponse testResponse = HttpExecuteResponse.builder()
                .responseBody(AbortableInputStream.create(new FileInputStream(filePath)))
                .response(SdkHttpResponse.builder()
                        .statusCode(200)
                        .build()
        ).build();

        assertEquals(requests.handleResponse(testResponse).length(), 7335);
    }

    @Test
    public void testHandleResponse_NonSuccessResponse() throws IOException {
        final String filePath = "test/data/SbomOutputExample.json";
        HttpExecuteResponse testResponse = HttpExecuteResponse.builder()
                .responseBody(AbortableInputStream.create(new FileInputStream(filePath)))
                .response(SdkHttpResponse.builder()
                        .statusCode(400)
                        .build()
                ).build();

        assertThrows(RuntimeException.class, () -> requests.handleResponse(testResponse));
    }

    @Test
    public void testHandleResponse_NoInputStream() throws IOException {
        final String filePath = "test/data/SbomOutputExample.json";
        HttpExecuteResponse testResponse = HttpExecuteResponse.builder()
                .responseBody(null)
                .response(SdkHttpResponse.builder()
                        .statusCode(200)
                        .build()
                ).build();

        assertThrows(RuntimeException.class, () -> requests.handleResponse(testResponse));
    }
}
