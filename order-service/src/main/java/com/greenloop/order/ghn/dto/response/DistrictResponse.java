package com.greenloop.order.ghn.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

@Data
public class DistrictResponse {

    @JsonProperty("DistrictID")
    private Integer districtId;

    @JsonProperty("ProvinceID")
    private Integer provinceId;

    @JsonProperty("DistrictName")
    private String districtName;

    @JsonProperty("Code")
    private Integer code;

    @JsonProperty("Type")
    private Integer type;

    @JsonProperty("SupportType")
    private Integer supportType;

    @JsonProperty("NameExtension")
    private List<String> nameExtension;

    @JsonProperty("IsEnable")
    private Integer isEnable;

    @JsonProperty("CanUpdateCOD")
    private String canUpdateCOD;

    @JsonProperty("Status")
    private Integer status;
}
