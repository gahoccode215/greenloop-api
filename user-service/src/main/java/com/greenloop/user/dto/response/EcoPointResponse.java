package com.greenloop.user.dto.response;

import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EcoPointResponse {
  private Long id;
  private Long userId;
  private Integer totalPoints;
  private Integer lifetimePoints;
  private String status;
  private List<Object> transactions;
}
