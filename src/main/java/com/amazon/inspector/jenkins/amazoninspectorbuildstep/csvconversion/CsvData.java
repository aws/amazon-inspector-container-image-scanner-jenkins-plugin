package com.amazon.inspector.jenkins.amazoninspectorbuildstep.csvconversion;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class CsvData {
    private String vulnerabilityId;
    private String severity;
    private String epssScore;
    private String published;
    private String modified;
    private String description;
    private String packageInstalledVersion;
    private String packagePath;
    private String packageFixedVersion;
    private String cwes;
    private String exploitAvailable;
    private String exploitLastSeen;
    private String file;
    private String lines;
}
