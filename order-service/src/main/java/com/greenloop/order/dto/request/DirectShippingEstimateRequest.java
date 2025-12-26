package com.greenloop.order.dto.request;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DirectShippingEstimateRequest {
    private Long productId;
    private Long cityId;
    private Long districtId;
}
