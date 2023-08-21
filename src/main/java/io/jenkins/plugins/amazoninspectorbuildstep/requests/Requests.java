package io.jenkins.plugins.amazoninspectorbuildstep.requests;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Charsets;
import com.google.common.io.CharStreams;
import io.jenkins.plugins.amazoninspectorbuildstep.exception.RetriesExceededLimitException;
import io.jenkins.plugins.amazoninspectorbuildstep.requests.helpers.HttpExecuteRequestHelper;
import io.jenkins.plugins.amazoninspectorbuildstep.requests.helpers.SignRequestHelper;
import io.jenkins.plugins.amazoninspectorbuildstep.requests.helpers.UnsignedRequestHelper;
import lombok.AllArgsConstructor;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.http.HttpExecuteResponse;
import software.amazon.awssdk.http.HttpStatusCode;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.apache.ApacheHttpClient;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.URISyntaxException;

@AllArgsConstructor
public class Requests {
    private AwsBasicCredentials credentials;
    private String sessionToken;
    private String sbomData;
    private PrintStream logger;
    private String region;

    public String requestSbom() throws RetriesExceededLimitException, InterruptedException, URISyntaxException,
            IOException {
        logger.println("Checking sbom for vulnerabilities.");

        SdkHttpFullRequest unsignedRequest = new UnsignedRequestHelper(logger, region, sessionToken, sbomData)
                .getRequest();
        SdkHttpFullRequest signedRequest = new SignRequestHelper(unsignedRequest, region, credentials).getRequest();

        SdkHttpClient client = ApacheHttpClient.builder().build();
        RetryWaitHandler retryHandler = new RetryWaitHandler(logger, 30000, 3, 120000);
        return handleRequest(client, signedRequest, retryHandler);
    }

    @VisibleForTesting
    protected String handleRequest(SdkHttpClient client, SdkHttpFullRequest signedRequest,
                                   RetryWaitHandler retryWaitHandler)
            throws IOException, RetriesExceededLimitException, InterruptedException {

        HttpExecuteResponse response;
        String responseBody;

        do {
            logger.printf("Requesting SBOM from Inspector API, attempt %d\n", retryWaitHandler.getNumRetries());

            response = client.prepareRequest(new HttpExecuteRequestHelper(signedRequest).getRequest()).call();
            responseBody = CharStreams.toString(new InputStreamReader(response.responseBody().orElse(null).delegate(),
                    Charsets.UTF_8));

            if (response.httpResponse().statusCode() == 200) {
                logger.println("Request responded OK");
            } else {
                logger.printf("Request failed - %s: %s\n", response.httpResponse().statusCode(),
                        response.httpResponse().statusText().orElse("No Status Text"));
                logger.printf("Response Body: \n%s", responseBody);

                retryWaitHandler.sleep();
            }
        } while (response.httpResponse().statusCode() != HttpStatusCode.OK && !retryWaitHandler.retriesExceedMaximum());

        if (retryWaitHandler.retriesExceedMaximum()) {
            throw new RetriesExceededLimitException("Number of retries for api exceeded limit, failing build");
        }

        return responseBody;
    }

}
