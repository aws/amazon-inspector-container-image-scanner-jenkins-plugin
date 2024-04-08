package com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.html.components;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import lombok.Builder;

@Builder
@SuppressFBWarnings
public class SeverityValues {
    public int critical;
    public int high;
    public int medium;
    public int low;
    public int other;
}
