package com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.html;

import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.html.components.HtmlVulnerability;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.html.components.ImageMetadata;
import com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.html.components.SeverityValues;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import lombok.Builder;

import java.util.List;

@Builder
@SuppressFBWarnings
public class HtmlData {
    public String artifactsPath;
    public String bomFormat;
    public String specVersion;
    public String version;
    public String updatedAt;
    public ImageMetadata imageMetadata;
    public SeverityValues severityValues;
    public List<HtmlVulnerability> vulnerabilities;
}

