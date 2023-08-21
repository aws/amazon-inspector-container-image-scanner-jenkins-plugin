package io.jenkins.plugins.amazoninspectorbuildstep.models.sbom;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
@Getter
@Setter
public class SbomData {
    private String status;
    private Sbom sbom;
}
