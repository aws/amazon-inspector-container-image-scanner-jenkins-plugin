package io.jenkins.plugins.amazoninspectorbuildstep.exception;

import io.jenkins.plugins.amazoninspectorbuildstep.AmazonInspectorBuilder;

public class MalformedScanOutputException extends Exception{
    public MalformedScanOutputException(String message) {
        super(message);

        AmazonInspectorBuilder.logger.println(message);
    }
}
