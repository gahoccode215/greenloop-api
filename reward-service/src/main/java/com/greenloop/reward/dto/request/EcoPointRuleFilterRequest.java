package com.greenloop.reward.dto.request;

import com.greenloop.reward.enums.EcoActionType;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class EcoPointRuleFilterRequest {
  private EcoActionType actionType;
  private String code;
  private String name;
  private Long categoryId;
}
