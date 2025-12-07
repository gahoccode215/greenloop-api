package com.greenloop.reward.dto.response;

import java.util.List;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Builder
public class EcoPointLeaderboardResponse {
  private Long currentUserId;
  private Integer currentUserRank;
  private Integer currentUserPoints;
  private List<EcoPointUserDTO> topUsers;
}
