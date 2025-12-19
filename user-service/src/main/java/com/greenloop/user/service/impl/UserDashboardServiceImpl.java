package com.greenloop.user.service.impl;

import com.greenloop.user.dto.response.dashboard.*;
import com.greenloop.user.repository.UserRepository;
import com.greenloop.user.service.UserDashboardService;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserDashboardServiceImpl implements UserDashboardService {

  private final UserRepository userRepository;

  @Override
  public UserDashboardOverviewResponse getDashboardOverview() {
    log.info("Fetching user dashboard overview");

    return UserDashboardOverviewResponse.builder()
        .totalUsers(getTotalUsers())
        .newUsersByPeriod(getNewUsersByPeriod())
        .usersByRole(getUsersByRole())
        .usersByStatus(getUsersByStatus())
        .newUsersTimeline(getNewUsersTimeline(30))
        .activeUsers(getActiveUsers())
        .build();
  }

  private Long getTotalUsers() {
    return userRepository.count();
  }

  private NewUsersByPeriod getNewUsersByPeriod() {
    LocalDateTime now = LocalDateTime.now();
    LocalDateTime startOfToday = LocalDate.now().atStartOfDay();
    LocalDateTime startOfWeek = now.minusDays(7);
    LocalDateTime startOfMonth = now.minusDays(30);
    LocalDateTime startOfLastMonth = now.minusDays(60);
    LocalDateTime endOfLastMonth = now.minusDays(30);

    return NewUsersByPeriod.builder()
        .today(userRepository.countByCreatedAtAfter(startOfToday))
        .thisWeek(userRepository.countByCreatedAtAfter(startOfWeek))
        .thisMonth(userRepository.countByCreatedAtAfter(startOfMonth))
        .lastMonth(userRepository.countByCreatedAtBetween(startOfLastMonth, endOfLastMonth))
        .build();
  }

  private Map<String, Long> getUsersByRole() {
    List<Object[]> results = userRepository.countUsersByRole();

    Map<String, Long> roleMap =
        results.stream().collect(Collectors.toMap(row -> (String) row[0], row -> (Long) row[1]));

    // Đảm bảo có đủ các role (nếu không có data thì = 0)
    roleMap.putIfAbsent("CUSTOMER", 0L);
    roleMap.putIfAbsent("STAFF", 0L);
    roleMap.putIfAbsent("MANAGER", 0L);
    roleMap.putIfAbsent("ADMIN", 0L);

    return roleMap;
  }

  private Map<String, Long> getUsersByStatus() {
    List<Object[]> results = userRepository.countUsersByStatus();

    Map<String, Long> statusMap =
        results.stream().collect(Collectors.toMap(row -> (String) row[0], row -> (Long) row[1]));

    // Đảm bảo có đủ các status (nếu không có data thì = 0)
    statusMap.putIfAbsent("ACTIVE", 0L);
    statusMap.putIfAbsent("INACTIVE", 0L);

    return statusMap;
  }

  private List<TimelineData> getNewUsersTimeline(int days) {
    LocalDateTime startDate = LocalDateTime.now().minusDays(days);
    List<Object[]> results = userRepository.getNewUsersTimeline(startDate);

    // Tạo map từ kết quả query
    Map<String, Long> dataMap =
        results.stream()
            .collect(
                Collectors.toMap(row -> row[0].toString(), row -> ((Number) row[1]).longValue()));

    // Fill missing dates với 0
    List<TimelineData> timeline = new ArrayList<>();
    LocalDate currentDate = LocalDate.now();

    for (int i = days - 1; i >= 0; i--) {
      LocalDate date = currentDate.minusDays(i);
      String dateStr = date.toString();

      timeline.add(
          TimelineData.builder().date(dateStr).count(dataMap.getOrDefault(dateStr, 0L)).build());
    }

    return timeline;
  }

  private ActiveUsersData getActiveUsers() {
    LocalDateTime now = LocalDateTime.now();
    LocalDateTime startOfToday = LocalDate.now().atStartOfDay();
    LocalDateTime startOfWeek = now.minusDays(7);
    LocalDateTime startOfMonth = now.minusDays(30);

    return ActiveUsersData.builder()
        .dau(userRepository.countByLastLoginAtAfter(startOfToday))
        .wau(userRepository.countByLastLoginAtAfter(startOfWeek))
        .mau(userRepository.countByLastLoginAtAfter(startOfMonth))
        .build();
  }
}
