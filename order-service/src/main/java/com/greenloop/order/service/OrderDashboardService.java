package com.greenloop.order.service;

import com.greenloop.order.dto.response.dashboard.OrderDashboardOverviewResponse;

public interface OrderDashboardService {
    OrderDashboardOverviewResponse getDashboardOverview();
}
