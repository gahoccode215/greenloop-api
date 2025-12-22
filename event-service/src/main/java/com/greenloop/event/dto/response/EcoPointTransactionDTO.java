package com.greenloop.event.dto.response;

import com.greenloop.event.enums.EcoPointType;
import com.greenloop.event.enums.SourceType;
import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class EcoPointTransactionDTO {
  private Long userId;
  private Integer points;
  private String description;
  private EcoPointType type;
  private SourceType sourceType;
  private Long sourceId;
}
