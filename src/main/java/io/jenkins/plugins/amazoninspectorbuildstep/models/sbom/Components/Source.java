package io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Components;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class Source {
    private String name;
    private String url;
}
