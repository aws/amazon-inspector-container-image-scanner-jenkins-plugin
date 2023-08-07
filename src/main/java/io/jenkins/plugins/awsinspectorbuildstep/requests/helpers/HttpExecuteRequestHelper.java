package io.jenkins.plugins.awsinspectorbuildstep.requests.helpers;

import lombok.Getter;
import software.amazon.awssdk.http.HttpExecuteRequest;
import software.amazon.awssdk.http.SdkHttpFullRequest;

public class HttpExecuteRequestHelper {
    @Getter
    HttpExecuteRequest request;

    public HttpExecuteRequestHelper(SdkHttpFullRequest signedRequest) {
        this.request = HttpExecuteRequest.builder().request(signedRequest)
                .contentStreamProvider(signedRequest.contentStreamProvider().orElse(null))
                .build();
    }
}
