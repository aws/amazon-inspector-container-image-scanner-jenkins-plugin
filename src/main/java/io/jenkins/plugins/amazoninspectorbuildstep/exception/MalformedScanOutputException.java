package io.jenkins.plugins.amazoninspectorbuildstep.exception;

public class MalformedScanOutputException extends Exception{
    public MalformedScanOutputException(String message) {
        super(message);
    }
}