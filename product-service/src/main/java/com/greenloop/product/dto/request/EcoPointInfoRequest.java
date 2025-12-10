package com.greenloop.product.dto.request;

import com.greenloop.product.enums.EcoActionType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EcoPointInfoRequest {
    private EcoActionType ecoActionType;
    private Long categoryId;
}
