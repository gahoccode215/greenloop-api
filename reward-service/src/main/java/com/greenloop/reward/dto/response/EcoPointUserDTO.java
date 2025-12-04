package com.greenloop.reward.dto.response;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class EcoPointUserDTO {
    private Long userId;
    private Long lifetimePoints;
}
