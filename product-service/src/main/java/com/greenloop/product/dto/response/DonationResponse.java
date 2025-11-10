package com.greenloop.product.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Builder
public class DonationResponse {
    private Long id;
    private String code;
    private Float totalWeight;
    private Integer totalEcoPoints;
    private Integer totalItems;

}
