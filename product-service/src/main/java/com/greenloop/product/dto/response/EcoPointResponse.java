package com.greenloop.product.dto.response;

import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class EcoPointResponse {
    private Long id;
    private Long categoryId;
    private String code;
    private String name;
    private String description;
    private EcoActionType actionType;
    private Integer minPoints;
    private Integer maxPoints;
    private Boolean isActive;
}
