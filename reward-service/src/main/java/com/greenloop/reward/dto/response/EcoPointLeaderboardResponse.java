package com.greenloop.reward.dto.response;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@Builder
public class EcoPointLeaderboardResponse {
    private Long currentUserId;
    private Integer currentUserRank;
    private Integer currentUserPoints;
    private List<EcoPointUserDTO> topUsers;
}
