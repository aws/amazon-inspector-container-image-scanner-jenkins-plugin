package io.jenkins.plugins.amazoninspectorbuildstep.models.sbom;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
@Builder
@Getter
@Setter
public class SbomData {
    private String status;
    private Sbom sbom;
}
