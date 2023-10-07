package io.jenkins.plugins.amazoninspectorbuildstep.requests.helpers;

import lombok.Getter;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.signer.Aws4Signer;
import software.amazon.awssdk.auth.signer.params.Aws4SignerParams;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.regions.Region;

public class SignRequestHelper {
    @Getter
    SdkHttpFullRequest request;

    public SignRequestHelper(SdkHttpFullRequest unsignedRequest, String region, AwsBasicCredentials credentials) {
        final String serviceName = "eevee";
        Aws4SignerParams signerParams = Aws4SignerParams.builder()
                .awsCredentials(credentials)
                .signingName(serviceName)
                .signingRegion(Region.of(region))
                .build();

        Aws4Signer signer = Aws4Signer.create();
        this.request = signer.sign(unsignedRequest, signerParams);
    }
}