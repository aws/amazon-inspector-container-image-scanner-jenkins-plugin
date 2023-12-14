package com.amazon.inspector.jenkins.amazoninspectorbuildstep.exception;

public class RetriesExceededLimitException extends Exception {
    public RetriesExceededLimitException(String errorMessage) {
        super(errorMessage);
    }
}
