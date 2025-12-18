package com.greenloop.product.dto.response;

import com.greenloop.product.enums.ConditionGrade;
import com.greenloop.product.enums.DonationItemStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Builder
public class DonationItemResponse {
    private Long id;
    private String code;
    private String name;
    private Integer ecoPoints;
    private String categoryName;
    private Long categoryId;
    private ConditionGrade conditionGrade;
    private String imageUrl;
    private DonationItemStatus status;
}
