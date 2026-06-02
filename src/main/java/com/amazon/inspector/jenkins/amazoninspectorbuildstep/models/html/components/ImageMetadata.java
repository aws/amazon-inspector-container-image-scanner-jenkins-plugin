package com.amazon.inspector.jenkins.amazoninspectorbuildstep.models.html.components;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import lombok.Builder;

/** Fields are serialized by Gson into the HTML report; SpotBugs can't see that usage. */
@SuppressFBWarnings("URF_UNREAD_PUBLIC_OR_PROTECTED_FIELD")
@Builder
public class ImageMetadata {
    public String id;
    public String tags;
    public String sha;
}
