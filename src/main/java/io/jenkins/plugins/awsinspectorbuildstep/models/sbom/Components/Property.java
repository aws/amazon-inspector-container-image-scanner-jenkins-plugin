package io.jenkins.plugins.awsinspectorbuildstep.models.sbom.Components;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Property {
    private String name;
    private String value;
}
