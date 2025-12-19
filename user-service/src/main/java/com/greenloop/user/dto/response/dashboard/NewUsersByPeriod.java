package com.greenloop.user.dto.response.dashboard;

import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NewUsersByPeriod {
  private Long today;
  private Long thisWeek;
  private Long thisMonth;
  private Long lastMonth;
}
