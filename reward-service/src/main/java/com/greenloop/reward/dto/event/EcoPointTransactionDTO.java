package com.greenloop.reward.dto.event;

import com.greenloop.reward.enums.EcoPointType;
import com.greenloop.reward.enums.SourceType;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class EcoPointTransactionDTO {
  private Long userId;
  private Integer points;
  private String description;
  private EcoPointType type;
  private SourceType sourceType;
  private Long sourceId;
}
