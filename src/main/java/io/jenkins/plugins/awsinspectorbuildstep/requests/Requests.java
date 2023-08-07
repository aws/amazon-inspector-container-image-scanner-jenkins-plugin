package io.jenkins.plugins.awsinspectorbuildstep.requests;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Charsets;
import com.google.common.io.CharStreams;
import io.jenkins.plugins.awsinspectorbuildstep.requests.helpers.HttpExecuteRequestHelper;
import io.jenkins.plugins.awsinspectorbuildstep.requests.helpers.SignRequestHelper;
import io.jenkins.plugins.awsinspectorbuildstep.requests.helpers.UnsignedRequestHelper;
import lombok.AllArgsConstructor;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.http.AbortableInputStream;
import software.amazon.awssdk.http.HttpExecuteRequest;
import software.amazon.awssdk.http.HttpExecuteResponse;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.URISyntaxException;
import java.util.Optional;

@AllArgsConstructor
public class Requests {
    private AwsBasicCredentials credentials;
    private String sessionToken;
    private String filePath;
    private PrintStream logger;
    public String getSbom() throws IOException, URISyntaxException {
        logger.println("Checking sbom for vulnerabilities.");

        SdkHttpFullRequest unsignedRequest = new UnsignedRequestHelper(logger, sessionToken, filePath).getRequest();
        SdkHttpFullRequest signedRequest = new SignRequestHelper(unsignedRequest, credentials).getRequest();
        SdkHttpClient client = ApacheHttpClient.builder().build();
        HttpExecuteRequest executeRequest = new HttpExecuteRequestHelper(signedRequest).getRequest();
        HttpExecuteResponse response = client.prepareRequest(executeRequest).call();

        return handleResponse(response);
    }

    @VisibleForTesting
    protected String handleResponse(HttpExecuteResponse response) throws IOException {
        SdkHttpResponse responseData = response.httpResponse();

        if (responseData.statusCode() == 200) {
            logger.println("Request responded OK");
        } else {
            logger.printf("Request failed with code %s and error %s\n",
                    responseData.statusCode(), responseData.statusText().orElse("No Status Text"));
            throw new RuntimeException();
        }

        Optional<AbortableInputStream> responseBodyInputStream = response.responseBody();
        if (responseBodyInputStream.isEmpty()) {
            logger.printf("No input stream was present in the response from the api.");
            throw new RuntimeException();
        }

        return CharStreams.toString(new InputStreamReader(responseBodyInputStream.orElse(null).delegate(),
                Charsets.UTF_8));
    }

}
