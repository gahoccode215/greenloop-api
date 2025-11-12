package com.greenloop.order.ghn.dto.response;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;

@Data
public class WardResponse {

    @JsonProperty("WardCode")
    private String wardCode;

    @JsonProperty("DistrictID")
    private Integer districtId;

    @JsonProperty("WardName")
    private String wardName;

    @JsonProperty("NameExtension")
    private List<String> nameExtension;

    @JsonProperty("CanUpdateCOD")
    private String canUpdateCOD;

    @JsonProperty("SupportType")
    private Integer supportType;

    @JsonProperty("Status")
    private Integer status;

    @JsonProperty("CreatedDate")
    private String createdDate;

    @JsonProperty("UpdatedDate")
    private String updatedDate;
}
