package com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class Rating {
    private Source source;
    private double score;
    private String severity;
    private String method;
    private String vector;
}
