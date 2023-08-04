package io.jenkins.plugins.awsinspectorbuildstep.requests;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Charsets;
import com.google.common.io.CharStreams;
import lombok.AllArgsConstructor;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.signer.Aws4Signer;
import software.amazon.awssdk.auth.signer.params.Aws4SignerParams;
import software.amazon.awssdk.http.HttpExecuteRequest;
import software.amazon.awssdk.http.HttpExecuteResponse;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.URI;
import java.time.Instant;

@AllArgsConstructor
public class Requests {
    private AwsBasicCredentials credentials;
    private String sessionToken;
    private String filePath;
    private PrintStream logger;

    public String getSbom() throws  IOException {
        logger.println("Checking sbom for vulnerabilities.");

        String serviceName = "eevee";
        URI endpoint = URI.create("https://prod.us-east-1.api.eevee.aws.dev/scan/sbom/cyclonedx");

        String xAmzDate = getXAmzDateString(Instant.now().toString());
        SdkHttpFullRequest request = buildRequest(endpoint, xAmzDate);
        SdkHttpFullRequest signedRequest = signRequest(serviceName, request);
        SdkHttpClient client = ApacheHttpClient.builder().build();
        HttpExecuteRequest executeRequest = buildExecuteRequest(signedRequest);
        HttpExecuteResponse response = client.prepareRequest(executeRequest).call();

        SdkHttpResponse responseData = response.httpResponse();

        if (responseData.statusCode() == 200) {
            logger.println("Request responded OK");
        } else {
            logger.printf("Request failed with code %s and error %s\n",
                    responseData.statusCode(), responseData.statusText().get());
        }
        InputStream responseBodyInputStream = response.responseBody().get().delegate();

        return CharStreams.toString(new InputStreamReader(responseBodyInputStream, Charsets.UTF_8));
    }

    @VisibleForTesting
    protected HttpExecuteRequest buildExecuteRequest(SdkHttpFullRequest signedRequest) {
        return HttpExecuteRequest.builder().request(signedRequest)
                .contentStreamProvider(signedRequest.contentStreamProvider().orElse(null))
                .build();
    }

    @VisibleForTesting
    protected SdkHttpFullRequest signRequest(String serviceName, SdkHttpFullRequest unsignedRequest) {
        Aws4SignerParams signerParams = Aws4SignerParams.builder()
                .awsCredentials(credentials)
                .signingName(serviceName)
                .signingRegion(Region.of("us-east-1"))
                .build();

        Aws4Signer signer = Aws4Signer.create();
        return signer.sign(unsignedRequest, signerParams);
    }

    @VisibleForTesting
    protected SdkHttpFullRequest buildRequest(URI endpoint, String xAmzDate) {
        SdkHttpFullRequest request = SdkHttpFullRequest.builder()
                .method(SdkHttpMethod.POST)
                .uri(endpoint)
                .putHeader("X-Amz-Security-Token", sessionToken)
                .putHeader("X-Amz-Date", xAmzDate)
                .contentStreamProvider(() -> {
                    try {
                        return new FileInputStream(filePath);
                    } catch (FileNotFoundException e) {
                        logger.printf("Couldn't find file at path %s", filePath);
                        throw new RuntimeException(e);
                    }
                })
                .build();

        return request;
    }

    @VisibleForTesting
    protected String getXAmzDateString(String currentDateUtc) {
        String[] split = currentDateUtc.split("[\\.\\-:]");
        split[split.length - 1] = "Z";
        return String.join("", split);
    }
}
