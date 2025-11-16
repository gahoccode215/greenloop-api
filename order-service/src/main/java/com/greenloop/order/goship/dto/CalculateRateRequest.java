package com.greenloop.order.goship.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CalculateRateRequest {

    @JsonProperty("from_district_id")
    private String fromDistrictId;

    @JsonProperty("to_district_id")
    private String toDistrictId;

    @JsonProperty("weight")
    private Integer weight; // gram

    @JsonProperty("length")
    private Integer length; // cm

    @JsonProperty("width")
    private Integer width; // cm

    @JsonProperty("height")
    private Integer height; // cm

    @JsonProperty("insurance_value")
    private Integer insuranceValue; // Giá trị bảo hiểm (optional)
}
