package com.greenloop.user.service;

import com.greenloop.user.dto.response.dashboard.UserDashboardOverviewResponse;

public interface UserDashboardService {
  UserDashboardOverviewResponse getDashboardOverview();
}
