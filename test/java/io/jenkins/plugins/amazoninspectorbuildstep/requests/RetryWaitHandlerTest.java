package io.jenkins.plugins.amazoninspectorbuildstep.requests;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RetryWaitHandlerTest {

    @Test
    public void testGetSleepTime_Success() {
        RetryWaitHandler retryWaitHandler = new RetryWaitHandler(System.out, 1000, 5, 60000);
        assertEquals(retryWaitHandler.getSleepTime(), 1000);
        retryWaitHandler.incrementRetries();
        assertEquals(retryWaitHandler.getSleepTime(), 4000);
        retryWaitHandler.incrementRetries();
        assertEquals(retryWaitHandler.getSleepTime(), 9000);
        retryWaitHandler.incrementRetries();
        assertEquals(retryWaitHandler.getSleepTime(), 16000);
        retryWaitHandler.incrementRetries();
        assertEquals(retryWaitHandler.getSleepTime(), 25000);
    }

    @Test
    public void testRetriesExceedMaximum_Success() {
        RetryWaitHandler retryWaitHandler = new RetryWaitHandler(System.out, 0, 1, 0);
        assertFalse(retryWaitHandler.retriesExceedMaximum());
        retryWaitHandler.incrementRetries();
        assertTrue(retryWaitHandler.retriesExceedMaximum());
    }
}
