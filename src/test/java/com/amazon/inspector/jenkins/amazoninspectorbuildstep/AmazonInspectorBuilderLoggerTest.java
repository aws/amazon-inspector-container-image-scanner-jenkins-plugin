package com.amazon.inspector.jenkins.amazoninspectorbuildstep;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AmazonInspectorBuilderLoggerTest {

    @AfterEach
    void tearDown() {
        AmazonInspectorBuilder.clearLogger();
    }

    @Test
    void getLogger_withoutSet_fallsBackToSystemOut() {
        AmazonInspectorBuilder.clearLogger();
        assertSame(System.out, AmazonInspectorBuilder.getLogger(),
                "Logging outside an active build should fall back to System.out, not throw or return null");
    }

    @Test
    void setLogger_thenGetLogger_returnsSameStream() {
        PrintStream stream = new PrintStream(new ByteArrayOutputStream());
        AmazonInspectorBuilder.setLogger(stream);
        assertSame(stream, AmazonInspectorBuilder.getLogger());
    }

    @Test
    void clearLogger_revertsToSystemOut() {
        AmazonInspectorBuilder.setLogger(new PrintStream(new ByteArrayOutputStream()));
        AmazonInspectorBuilder.clearLogger();
        assertSame(System.out, AmazonInspectorBuilder.getLogger());
    }

    /**
     * Reproduces the concurrent-build scenario: two threads each set their own logger and write to
     * it. With a plain static field the writes would interleave into a single stream; with the
     * ThreadLocal each thread only ever sees its own stream.
     */
    @Test
    void concurrentBuilds_doNotShareLoggerState() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            ByteArrayOutputStream bufferA = new ByteArrayOutputStream();
            ByteArrayOutputStream bufferB = new ByteArrayOutputStream();
            PrintStream streamA = new PrintStream(bufferA, true, StandardCharsets.UTF_8);
            PrintStream streamB = new PrintStream(bufferB, true, StandardCharsets.UTF_8);

            CountDownLatch bothAssigned = new CountDownLatch(2);
            CountDownLatch done = new CountDownLatch(2);
            AtomicReference<PrintStream> seenByA = new AtomicReference<>();
            AtomicReference<PrintStream> seenByB = new AtomicReference<>();

            pool.submit(() -> {
                AmazonInspectorBuilder.setLogger(streamA);
                bothAssigned.countDown();
                try {
                    // Wait until the other thread has also set its logger, maximizing the chance a
                    // shared static field would be observed cross-thread.
                    bothAssigned.await(5, TimeUnit.SECONDS);
                    AmazonInspectorBuilder.getLogger().print("A");
                    seenByA.set(AmazonInspectorBuilder.getLogger());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    AmazonInspectorBuilder.clearLogger();
                    done.countDown();
                }
            });

            pool.submit(() -> {
                AmazonInspectorBuilder.setLogger(streamB);
                bothAssigned.countDown();
                try {
                    bothAssigned.await(5, TimeUnit.SECONDS);
                    AmazonInspectorBuilder.getLogger().print("B");
                    seenByB.set(AmazonInspectorBuilder.getLogger());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    AmazonInspectorBuilder.clearLogger();
                    done.countDown();
                }
            });

            assertTrue(done.await(10, TimeUnit.SECONDS), "Both build threads should finish");

            // Each thread saw exactly its own stream...
            assertSame(streamA, seenByA.get());
            assertSame(streamB, seenByB.get());
            // ...and each stream received only its own thread's output, no cross-talk.
            assertEquals("A", bufferA.toString(StandardCharsets.UTF_8));
            assertEquals("B", bufferB.toString(StandardCharsets.UTF_8));
        } finally {
            pool.shutdownNow();
        }
    }
}
