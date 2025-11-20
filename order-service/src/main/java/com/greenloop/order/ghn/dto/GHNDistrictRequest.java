package com.greenloop.order.ghn.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class GHNDistrictRequest {

    @JsonProperty("province_id")
    private Integer provinceId;
}
