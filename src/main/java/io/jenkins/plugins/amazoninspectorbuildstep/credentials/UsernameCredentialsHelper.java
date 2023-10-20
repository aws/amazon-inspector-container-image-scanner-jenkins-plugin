package io.jenkins.plugins.amazoninspectorbuildstep.credentials;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import hudson.model.Job;
import hudson.security.ACL;

import java.io.PrintStream;
import java.util.Collections;
import java.util.List;

import static io.jenkins.plugins.amazoninspectorbuildstep.AmazonInspectorBuilder.logger;

public class UsernameCredentialsHelper {
    private List<UsernamePasswordCredentials>  credentials;

    public UsernameCredentialsHelper(Job<?, ?> job) {
        this.credentials = CredentialsProvider.lookupCredentials(
                UsernamePasswordCredentials.class,
                job.getParent(),
                ACL.SYSTEM,
                Collections.emptyList()
        );
    }

    public String getKeyFromStore(String username) {
        UsernamePasswordCredentials credential = credentials.stream()
                .filter(cred -> cred.getUsername().equals(username))
                .findFirst()
                .orElse(null);

        if (credential == null) {
            return null;
        }

        return credential.getPassword().getPlainText();
    }
}
