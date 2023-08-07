package io.jenkins.plugins.awsinspectorbuildstep.requests.helpers;

import com.google.common.annotations.VisibleForTesting;
import lombok.Getter;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

public class UnsignedRequestHelper {
    @Getter
    SdkHttpFullRequest request;
    public UnsignedRequestHelper(PrintStream logger, String sessionToken, String filePath) throws URISyntaxException {
        final String endpoint = "https://prod.us-east-1.api.eevee.aws.dev/scan/sbom/cyclonedx";
        String xAmzDate = getXAmzDateString(Date.from(Instant.now()));

        this.request = SdkHttpFullRequest.builder()
                .method(SdkHttpMethod.POST)
                .uri(new URI(endpoint))
                .putHeader("X-Amz-Security-Token", sessionToken)
                .putHeader("X-Amz-Date", xAmzDate)
                .contentStreamProvider(() -> {
                    try {
                        return new FileInputStream(filePath);
                    } catch (FileNotFoundException e) {
                        logger.printf("Couldn't find file at path %s", filePath);
                        throw new RuntimeException(e);
                    }
                })
                .build();
    }

    @VisibleForTesting
    protected static String getXAmzDateString(Date currentDateUtc) {
        DateFormat formatter = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'", Locale.ROOT);
        formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
        return formatter.format(currentDateUtc);
    }
}
