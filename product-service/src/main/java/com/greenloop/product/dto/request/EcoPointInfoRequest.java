package com.greenloop.product.dto.request;

import com.greenloop.product.enums.EcoActionType;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class EcoPointInfoRequest {
    private EcoActionType ecoActionType;
    private Long categoryId;
}
