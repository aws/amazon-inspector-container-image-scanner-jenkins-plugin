package io.jenkins.plugins.amazoninspectorbuildstep.models.html.components;

import lombok.Builder;

@Builder
public class SeverityValues {
    public int critical;
    public int high;
    public int medium;
    public int low;
}
