package io.jenkins.plugins.amazoninspectorbuildstep.exception;

import io.jenkins.plugins.amazoninspectorbuildstep.AmazonInspectorBuilder;

public class BomermanNotFoundException extends Exception {
    public BomermanNotFoundException(String message) {
        super(message);

        AmazonInspectorBuilder.logger.println(message);
    }
}
