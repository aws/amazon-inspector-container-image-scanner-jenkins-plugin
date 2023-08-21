package io.jenkins.plugins.amazoninspectorbuildstep.requests.helpers;

import com.google.common.io.CharStreams;
import jline.internal.InputStreamReader;
import org.junit.Assert;
import org.junit.Test;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;

import java.io.IOException;
import java.io.PrintStream;
import java.net.URISyntaxException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;

import static io.jenkins.plugins.amazoninspectorbuildstep.requests.helpers.UnsignedRequestHelper.getXAmzDateString;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class UnsignedRequestHelperTest {
    @Test
    public void testGetXAmzDateString() {
        LocalDateTime date = LocalDateTime.parse("2023-08-04T18:56:53.531004");
        Assert.assertEquals(getXAmzDateString(Date.from(date.toInstant(ZoneOffset.UTC))), "20230804T185653Z");
    }

    @Test
    public void testBuildRequest_Success() throws IOException, URISyntaxException {
        String filePath = "/Users/waltwilo/workplace/EeveeCICDPlugin/src/EeveeCICDJenkinsPlugin/results/" +
                "bomerman_results-tar.json";
        String date = getXAmzDateString(Date.from(Instant.now()));
        SdkHttpFullRequest request = new UnsignedRequestHelper(new PrintStream(System.out), "","test",
                filePath).getRequest();
        assertEquals(request.headers().get("X-Amz-Date"), List.of(date));
        assertEquals(request.headers().get("X-Amz-Security-Token"), List.of("test"));
        assertEquals(request.host(), "prod.us-east-1.api.eevee.aws.dev");
        assertEquals(request.encodedPath(), "/scan/sbom/cyclonedx");
        assertEquals(request.method(), SdkHttpMethod.POST);

        List<String> requestBody = CharStreams.readLines(
                new InputStreamReader(request.contentStreamProvider().get().newStream()));
        assertEquals(requestBody.size(), 357);
    }
}
