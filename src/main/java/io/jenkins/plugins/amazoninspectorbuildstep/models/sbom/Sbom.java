package io.jenkins.plugins.amazoninspectorbuildstep.models.sbom;

import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Components.Component;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Components.Metadata;
import io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Components.Vulnerability;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@Builder
public class Sbom {
    private String bomFormat;
    private String specVersion;
    private int version;
    private String serialNumber;
    private Metadata metadata;
    private List<Component> components;
    private List<Vulnerability> vulnerabilities;
}