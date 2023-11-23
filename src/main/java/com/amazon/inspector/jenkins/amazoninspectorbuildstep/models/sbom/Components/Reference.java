package com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.sbom.Components;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Reference {
    private String id;
    private Source source;
}
