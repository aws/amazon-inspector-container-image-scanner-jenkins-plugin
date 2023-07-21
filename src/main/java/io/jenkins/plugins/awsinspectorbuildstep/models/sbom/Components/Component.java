package io.jenkins.plugins.awsinspectorbuildstep.models.sbom.Components;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Component {
    private String bomRef;
    private String type;
    private String name;
    private String purl;
}
