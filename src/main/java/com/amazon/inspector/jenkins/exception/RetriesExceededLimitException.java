package com.amazon.inspector.jenkins.exception;

public class RetriesExceededLimitException extends Exception {
    public RetriesExceededLimitException(String errorMessage) {
        super(errorMessage);
    }
}
