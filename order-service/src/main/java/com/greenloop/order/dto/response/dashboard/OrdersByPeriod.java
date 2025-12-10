package com.greenloop.order.dto.response.dashboard;

import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OrdersByPeriod {

    private Long today;        // Hôm nay
    private Long thisWeek;     // Tuần này (7 ngày qua)
    private Long thisMonth;    // Tháng này (30 ngày qua)
}
