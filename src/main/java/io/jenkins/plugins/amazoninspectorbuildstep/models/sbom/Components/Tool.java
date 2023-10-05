package io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Components;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
// Currently unused to trim sbom size
public class Tool {
    private String name;
    private String vendor;
    private String version;
}
