package com.greenloop.order.dto.response.dashboard;

import lombok.*;

import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OrderDashboardOverviewResponse {

    // Tổng quan đơn hàng
    private Long totalOrders;
    private OrdersByPeriod ordersByPeriod;

    // Doanh thu
    private RevenueStats revenueStats;

    // Phân bố theo trạng thái
    private OrderStatusDistribution statusDistribution;

    // Phân bố theo loại đơn
    private Map<String, Long> ordersByType;
}
