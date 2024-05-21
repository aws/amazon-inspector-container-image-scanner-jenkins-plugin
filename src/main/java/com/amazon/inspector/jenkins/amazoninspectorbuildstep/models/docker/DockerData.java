package com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.docker;

import lombok.Builder;

@Builder
public class DockerData {
    String vulnerabilityId;
    String filename;
    String lines;
    String severity;
    String description;
}
