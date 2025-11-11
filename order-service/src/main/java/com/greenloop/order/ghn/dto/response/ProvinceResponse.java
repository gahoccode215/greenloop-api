package com.greenloop.order.ghn.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

@Data
public class ProvinceResponse {

    @JsonProperty("ProvinceID")
    private Integer provinceId;

    @JsonProperty("ProvinceName")
    private String provinceName;

    @JsonProperty("Code")
    private String code;

    @JsonProperty("NameExtension")
    private List<String> nameExtension;

    @JsonProperty("IsEnable")
    private Integer isEnable;

    @JsonProperty("RegionID")
    private Integer regionId;

    @JsonProperty("RegionCPN")
    private Integer regionCPN;

    @JsonProperty("CanUpdateCOD")
    private Boolean canUpdateCOD;

    @JsonProperty("Status")
    private Integer status;
}
