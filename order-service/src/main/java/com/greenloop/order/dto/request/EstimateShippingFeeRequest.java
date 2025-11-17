package com.greenloop.order.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EstimateShippingFeeRequest {

    @NotBlank(message = "Mã tỉnh/thành không được để trống")
    private String cityCode;

    @NotBlank(message = "Mã quận/huyện không được để trống")
    private String districtCode;
}
