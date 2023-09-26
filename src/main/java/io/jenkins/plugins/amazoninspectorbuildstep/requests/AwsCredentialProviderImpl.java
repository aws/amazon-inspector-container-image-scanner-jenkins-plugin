package io.jenkins.plugins.amazoninspectorbuildstep.requests;

import lombok.AllArgsConstructor;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;

@AllArgsConstructor
public class AwsCredentialProviderImpl implements AwsCredentialsProvider {
    private String accessKeyId;
    private String secretAccessKey;

    @Override
    public AwsCredentials resolveCredentials() {
        return new AwsCredentials() {
            @Override
            public String accessKeyId() {
                return accessKeyId;
            }

            @Override
            public String secretAccessKey() {
                return secretAccessKey;
            }
        };
    }
}
