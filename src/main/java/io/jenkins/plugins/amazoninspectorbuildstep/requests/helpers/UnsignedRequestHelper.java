package io.jenkins.plugins.amazoninspectorbuildstep.requests.helpers;

import com.google.common.annotations.VisibleForTesting;
import lombok.Getter;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;

import java.io.ByteArrayInputStream;
import java.io.PrintStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

public class UnsignedRequestHelper {
    @Getter
    SdkHttpFullRequest request;
    public UnsignedRequestHelper(PrintStream logger, String region, String sessionToken, String sbomData) throws URISyntaxException {
        final String endpoint = String.format("https://prod.%s.api.eevee.aws.dev/scan/sbom/cyclonedx", region);
        String xAmzDate = getXAmzDateString(Date.from(Instant.now()));

        this.request = SdkHttpFullRequest.builder()
                .method(SdkHttpMethod.POST)
                .uri(new URI(endpoint))
                .putHeader("X-Amz-Security-Token", sessionToken)
                .putHeader("X-Amz-Date", xAmzDate)
                .contentStreamProvider(() -> new ByteArrayInputStream(sbomData.getBytes(StandardCharsets.UTF_8)))
                .build();
    }

    @VisibleForTesting
    protected static String getXAmzDateString(Date currentDateUtc) {
        DateFormat formatter = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'", Locale.ROOT);
        formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
        return formatter.format(currentDateUtc);
    }
}
