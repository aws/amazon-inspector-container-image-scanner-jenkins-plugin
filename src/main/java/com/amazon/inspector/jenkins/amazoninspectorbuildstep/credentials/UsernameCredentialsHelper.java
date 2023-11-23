package com.amazon.inspector.jenkins.amazoninspectorbuildstep.credentials;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials;
import hudson.model.Job;
import hudson.security.ACL;

import java.util.Collections;
import java.util.List;


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

    public String getPassword(String username) {
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
