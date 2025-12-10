package com.greenloop.user.dto.response.dashboard;


import lombok.*;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDashboardOverviewResponse {
    private Long totalUsers;
    private NewUsersByPeriod newUsersByPeriod;
    private Map<String, Long> usersByRole;
    private Map<String, Long> usersByStatus;
    private List<TimelineData> newUsersTimeline;
    private ActiveUsersData activeUsers;
}
