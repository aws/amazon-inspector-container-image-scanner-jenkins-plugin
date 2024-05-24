package com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.docker;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import lombok.Builder;

@Builder
@SuppressFBWarnings
public class DockerData {
    String vulnerabilityId;
    String filename;
    String lines;
    String severity;
    String description;
}
