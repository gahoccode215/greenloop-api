package com.greenloop.product.dto.response;

import com.greenloop.product.enums.ConditionGrade;
import com.greenloop.product.enums.DonationItemStatus;
import lombok.Builder;
import lombok.Data;

import java.util.Map;

@Data
@Builder
public class DonationStatisticsResponse {
    private Long totalDonations;
    private Long totalDonationItems;
    private Map<DonationItemStatus, Long> itemsByStatus;
    private Map<ConditionGrade, Long> itemsByCondition;
}
