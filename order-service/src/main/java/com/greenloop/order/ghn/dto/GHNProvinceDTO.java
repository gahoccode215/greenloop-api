package com.greenloop.order.ghn.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import java.util.List;

@Data
public class GHNProvinceDTO {

    @JsonProperty("ProvinceID")
    private Integer provinceId;

    @JsonProperty("ProvinceName")
    private String provinceName;

    @JsonProperty("CountryID")
    private Integer countryId;

    @JsonProperty("Code")
    private String code;

    @JsonProperty("NameExtension")
    private List<String> nameExtension;

    @JsonProperty("IsEnable")
    private Integer isEnable;

    @JsonProperty("RegionID")
    private Integer regionId;

    @JsonProperty("UpdatedBy")
    private Integer updatedBy;

    @JsonProperty("CreatedAt")
    private String createdAt;

    @JsonProperty("UpdatedAt")
    private String updatedAt;

    @JsonProperty("CanUpdateCOD")
    private Boolean canUpdateCOD;

    @JsonProperty("Status")
    private Integer status;
}
