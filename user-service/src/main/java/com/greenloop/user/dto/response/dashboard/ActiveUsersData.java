package com.greenloop.user.dto.response.dashboard;

import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ActiveUsersData {
  private Long dau; // Daily Active Users
  private Long wau; // Weekly Active Users
  private Long mau; // Monthly Active Users
}
