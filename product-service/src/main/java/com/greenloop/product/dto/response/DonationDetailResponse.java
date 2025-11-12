package com.greenloop.product.dto.response;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Builder
public class DonationDetailResponse {
    private Long id;
    private String code;
    private Float totalWeight;
    private Integer totalEcoPoints;
    private Integer totalItems;
    private Long inspectedBy;
    private String inspectedName;
    private Long eventId;
    private Long userId;
    private List<DonationItemResponse> donationItems;

}
