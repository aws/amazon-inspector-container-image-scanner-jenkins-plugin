package io.jenkins.plugins.amazoninspectorbuildstep.models.html;

import io.jenkins.plugins.amazoninspectorbuildstep.models.html.components.HtmlVulnerability;
import io.jenkins.plugins.amazoninspectorbuildstep.models.html.components.ImageMetadata;
import io.jenkins.plugins.amazoninspectorbuildstep.models.html.components.SeverityValues;
import lombok.Builder;

import java.util.List;

@Builder
public class HtmlData {
    public String jsonFilePath;
    public String csvFilePath;
    public String bomFormat;
    public String specVersion;
    public String version;
    public ImageMetadata imageMetadata;
    public SeverityValues severityValues;
    public List<HtmlVulnerability> vulnerabilities;
}

