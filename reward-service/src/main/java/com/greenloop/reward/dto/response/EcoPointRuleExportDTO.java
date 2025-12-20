package com.greenloop.reward.dto.response;

import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class EcoPointRuleExportDTO {
    private String ruleId;
    private String code;
    private String name;
    private String description;
    private String actionType;
    private String minPoints;
    private String maxPoints;
    private String categoryId;
    private String categoryName;
    private String createdAt;
    private String updatedAt;
}