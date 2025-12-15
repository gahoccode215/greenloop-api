package com.greenloop.order.dto.response.dashboard;

import lombok.*;
import java.math.BigDecimal;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RevenueStats {

    private BigDecimal totalRevenue;     // Tổng doanh thu (tất cả COMPLETED)
    private BigDecimal revenueToday;     // Doanh thu hôm nay
    private BigDecimal revenueThisWeek;  // Doanh thu tuần này
    private BigDecimal revenueThisMonth; // Doanh thu tháng này
    private BigDecimal averageOrderValue; // AOV (Average Order Value)
}
