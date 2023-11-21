package com.amazon.inspector.jenkins.models.sbom.Components;

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
