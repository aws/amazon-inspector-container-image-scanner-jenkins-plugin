package com.amazon.inspector.jenkins.amazoninspectorbuildstep;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Sbom;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.SbomData;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Rating;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Source;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components.Vulnerability;
import hudson.model.TaskListener;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AmazonInspectorBuilderEpssTest {

    private TaskListener listener;
    private Method assessMethod;

    @Before
    public void setUp() throws Exception {
        listener = mock(TaskListener.class);
        when(listener.getLogger()).thenReturn(new PrintStream(new ByteArrayOutputStream()));

        assessMethod = AmazonInspectorBuilder.class.getDeclaredMethod(
                "assessCVEsAgainstEPSS", TaskListener.class, Double.class, SbomData.class);
        assessMethod.setAccessible(true);
    }

    @Test
    public void emptyVulnerabilitiesReturnsFalse() throws Exception {
        assertFalse(invoke(builder(false, ""), 0.5, sbomData(Collections.emptyList())));
    }

    @Test
    public void nullVulnerabilitiesReturnsFalse() throws Exception {
        assertFalse(invoke(builder(false, ""), 0.5, sbomData(null)));
    }

    @Test
    public void vulnAboveThresholdReturnsTrue() throws Exception {
        List<Vulnerability> vulns = Collections.singletonList(epssVuln("CVE-1", 0.8));
        assertTrue(invoke(builder(false, ""), 0.5, sbomData(vulns)));
    }

    @Test
    public void vulnBelowThresholdReturnsFalse() throws Exception {
        List<Vulnerability> vulns = Collections.singletonList(epssVuln("CVE-1", 0.1));
        assertFalse(invoke(builder(false, ""), 0.5, sbomData(vulns)));
    }

    @Test
    public void vulnEqualToThresholdReturnsTrue() throws Exception {
        List<Vulnerability> vulns = Collections.singletonList(epssVuln("CVE-1", 0.5));
        assertTrue(invoke(builder(false, ""), 0.5, sbomData(vulns)));
    }

    @Test
    public void nullEpssScoreIsSkipped() throws Exception {
        List<Vulnerability> vulns = Collections.singletonList(noEpssVuln("CVE-1"));
        assertFalse(invoke(builder(false, ""), 0.5, sbomData(vulns)));
    }

    @Test
    public void suppressedCveAboveThresholdIsSkippedWhenSuppressionEnabled() throws Exception {
        List<Vulnerability> vulns = Collections.singletonList(epssVuln("CVE-1", 0.9));
        assertFalse(invoke(builder(true, "CVE-1"), 0.5, sbomData(vulns)));
    }

    @Test
    public void suppressedCveAboveThresholdIsCountedWhenSuppressionDisabled() throws Exception {
        List<Vulnerability> vulns = Collections.singletonList(epssVuln("CVE-1", 0.9));
        assertTrue(invoke(builder(false, "CVE-1"), 0.5, sbomData(vulns)));
    }

    @Test
    public void mixOfSuppressedAndBreachingCves() throws Exception {
        List<Vulnerability> vulns = Arrays.asList(
                epssVuln("CVE-1", 0.9),
                epssVuln("CVE-2", 0.8),
                epssVuln("CVE-3", 0.1));
        assertTrue(invoke(builder(true, "CVE-1"), 0.5, sbomData(vulns)));
    }

    @Test
    public void allSuppressedReturnsFalseEvenWhenAboveThreshold() throws Exception {
        List<Vulnerability> vulns = Arrays.asList(
                epssVuln("CVE-1", 0.9),
                epssVuln("CVE-2", 0.8));
        assertFalse(invoke(builder(true, "CVE-1,CVE-2"), 0.5, sbomData(vulns)));
    }

    @Test
    public void suppressionMatchIsCaseInsensitive() throws Exception {
        List<Vulnerability> vulns = Collections.singletonList(epssVuln("cve-2024-1234", 0.9));
        assertFalse(invoke(builder(true, "CVE-2024-1234"), 0.5, sbomData(vulns)));
    }

    private boolean invoke(AmazonInspectorBuilder builder, double threshold, SbomData data) throws Exception {
        return (boolean) assessMethod.invoke(builder, listener, threshold, data);
    }

    private static AmazonInspectorBuilder builder(boolean suppressionEnabled, String suppressedList) {
        return new AmazonInspectorBuilder(
                "test", "test", "container", false, "", "us-east-1", "", "", "",
                "automatic", "", 0, 0, 0, 0, "", "", 0.5, suppressedList,
                suppressionEnabled, false, "", false, true, true);
    }

    private static SbomData sbomData(List<Vulnerability> vulnerabilities) {
        return SbomData.builder().sbom(Sbom.builder().vulnerabilities(vulnerabilities).build()).build();
    }

    private static Vulnerability epssVuln(String id, double score) {
        Rating epss = Rating.builder().source(Source.builder().name("EPSS").build()).score(score).build();
        return Vulnerability.builder().id(id).ratings(Collections.singletonList(epss)).build();
    }

    private static Vulnerability noEpssVuln(String id) {
        return Vulnerability.builder().id(id).ratings(Collections.emptyList()).build();
    }
}
