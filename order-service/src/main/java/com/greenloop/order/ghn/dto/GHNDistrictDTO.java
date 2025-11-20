package com.greenloop.order.ghn.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import java.util.List;

@Data
public class GHNDistrictDTO {

    @JsonProperty("DistrictID")
    private Integer districtId;

    @JsonProperty("ProvinceID")
    private Integer provinceId;

    @JsonProperty("DistrictName")
    private String districtName;

    @JsonProperty("Code")
    private String code;

    @JsonProperty("Type")
    private Integer type;

    @JsonProperty("SupportType")
    private Integer supportType; // 0:Khóa tuyến, 1:Lấy/Trả, 2:Giao, 3:Lấy/Giao/Trả

    @JsonProperty("NameExtension")
    private List<String> nameExtension;

    @JsonProperty("IsEnable")
    private Integer isEnable;

    @JsonProperty("CanUpdateCOD")
    private String canUpdateCOD;

    @JsonProperty("Status")
    private Integer status; // 1:Mở tuyến, 2:Khóa tuyến

    @JsonProperty("CreatedDate")
    private String createdDate;

    @JsonProperty("UpdatedDate")
    private String updatedDate;
}
