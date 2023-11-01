package io.jenkins.plugins.amazoninspectorbuildstep.credentials;

import com.amazonaws.auth.AWSSessionCredentials;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.auth.STSAssumeRoleSessionCredentialsProvider;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import hudson.security.ACL;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import hudson.model.Job;

import java.io.PrintStream;
import java.util.Collections;
import java.util.List;

public class StringCredentialsHelper {
    private String region;
    private List<StringCredentials>  credentials;
    public StringCredentialsHelper(PrintStream logger, Job<?, ?> job, String region) {
        this.credentials = CredentialsProvider.lookupCredentials(
                StringCredentials.class,
                job.getParent(),
                ACL.SYSTEM,
                Collections.emptyList()
        );

        this.region = region;
    }

    public String getKeyFromStore(String keyId) {
        return credentials.stream()
                .filter(cred -> cred.getId().equals(keyId))
                .findFirst()
                .orElse(null).getSecret().getPlainText();
    }

    public AWSSessionCredentials getCredentialsFromRole(String roleArn) {
        String stsEndpoint = String.format("sts.%s.amazonaws.com",
                region);

        if (region.contains("cn")) {
            stsEndpoint += ".cn";
        }

        AWSSecurityTokenService sts = AWSSecurityTokenServiceClientBuilder.standard()
                .withCredentials(new DefaultAWSCredentialsProviderChain())
                .withEndpointConfiguration(new AwsClientBuilder.EndpointConfiguration(stsEndpoint, region)).build();

        String ssmSessionName = "AmazonInspectorCICD";

        STSAssumeRoleSessionCredentialsProvider credentialsProvider = new STSAssumeRoleSessionCredentialsProvider
                .Builder(roleArn, ssmSessionName)
                .withStsClient(sts)
                .build();

        return credentialsProvider.getCredentials();
    }
}
