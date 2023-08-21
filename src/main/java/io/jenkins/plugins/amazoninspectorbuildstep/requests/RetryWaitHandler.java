package io.jenkins.plugins.amazoninspectorbuildstep.requests;

import com.google.common.annotations.VisibleForTesting;
import lombok.Getter;

import java.io.PrintStream;

public class RetryWaitHandler {
    private final PrintStream logger;
    private final int sleepTimeMs;
    private final int maxRetries;
    private final int maxBackoff;
    @Getter
    private int numRetries;

    public RetryWaitHandler(PrintStream logger, int sleepTimeMs, int maxRetries, int maxBackoff) {
        this.logger = logger;
        this.sleepTimeMs = sleepTimeMs;
        this.maxRetries = maxRetries;
        this.maxBackoff = maxBackoff;
        this.numRetries = 0;
    }

    public int getSleepTime() {
        int exponentialSleepTime = (int) (Math.pow(numRetries + 1, 2) * sleepTimeMs);
        return Math.min(exponentialSleepTime, maxBackoff);
    }

    public void sleep() throws InterruptedException {
        int exponentialSleepTime = getSleepTime();

        logger.printf("Sleeping for %d secords\n", exponentialSleepTime/1000);
        Thread.sleep(exponentialSleepTime);
        numRetries++;
    }

    public boolean retriesExceedMaximum() {
        return numRetries >= maxRetries;
    }

    @VisibleForTesting
    protected void incrementRetries() {
        numRetries++;
    }

}
