package com.amazon.inspector.jenkins.exception;

public class MalformedScanOutputException extends Exception{
    public MalformedScanOutputException(String message) {
        super(message);
    }
}