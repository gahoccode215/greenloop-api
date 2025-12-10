package com.greenloop.user.dto.response.dashboard;

import lombok.*;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ActiveUsersData {
    private Long dau;  // Daily Active Users
    private Long wau;  // Weekly Active Users
    private Long mau;  // Monthly Active Users
}
