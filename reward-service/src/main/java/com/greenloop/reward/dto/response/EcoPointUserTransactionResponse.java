package com.greenloop.reward.dto.response;

import com.greenloop.reward.enums.EcoPointType;
import com.greenloop.reward.enums.SourceType;
import lombok.*;

import java.time.LocalDateTime;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class EcoPointUserTransactionResponse {
    private Long id;
    private String userId;
    private Integer points;
    private EcoPointType type;
    private SourceType sourceType;
    private Long sourceId;
    private String description;
    private LocalDateTime createdAt;
}
