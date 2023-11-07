package io.jenkins.plugins.amazoninspectorbuildstep.models.sbom.Components;

import com.google.gson.annotations.SerializedName;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@Builder
public class Component {
    @SerializedName("bom-ref")
    private String bomRef;
    private String type;
    private String name;
    private String purl;
    private List<Property> properties;
}
