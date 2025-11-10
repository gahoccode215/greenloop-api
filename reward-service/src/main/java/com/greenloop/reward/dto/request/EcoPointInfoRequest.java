package com.greenloop.reward.dto.request;

import com.greenloop.reward.enums.EcoActionType;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class EcoPointInfoRequest {
    private EcoActionType ecoActionType;
    private Long categoryId;
}