package com.greenloop.order.ghn.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import java.util.List;

@Data
public class GHNWardDTO {

    @JsonProperty("WardCode")
    private Integer wardCode;

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
