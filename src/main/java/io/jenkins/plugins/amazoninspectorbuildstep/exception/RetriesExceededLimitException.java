package io.jenkins.plugins.amazoninspectorbuildstep.exception;

public class RetriesExceededLimitException extends Exception {
    public RetriesExceededLimitException(String errorMessage) {
        super(errorMessage);
    }
}
