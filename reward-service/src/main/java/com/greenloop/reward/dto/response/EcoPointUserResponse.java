package com.greenloop.reward.dto.response;

import com.greenloop.reward.enums.EcoPointStatus;
import lombok.*;

import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class EcoPointUserResponse {
    private Long id;
    private Long userId;
    private Integer totalPoints;
    private Integer lifetimePoints;
    private EcoPointStatus status;
    private List<EcoPointUserTransactionResponse> transactions;
}
