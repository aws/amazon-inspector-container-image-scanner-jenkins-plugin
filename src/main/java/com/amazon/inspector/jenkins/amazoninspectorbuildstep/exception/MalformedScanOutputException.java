package com.amazon.inspector.jenkins.amazoninspectorbuildstep.exception;

public class MalformedScanOutputException extends Exception{
    public MalformedScanOutputException(String message) {
        super(message);
    }
}