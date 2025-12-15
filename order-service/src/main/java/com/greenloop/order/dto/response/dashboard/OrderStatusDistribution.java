package com.greenloop.order.dto.response.dashboard;

import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OrderStatusDistribution {

    private Long pending;           // Chờ xử lý (PENDING)
    private Long processing;        // Đang xử lý (CONFIRMED, PROCESSING, READY_TO_SHIP)
    private Long shipping;          // Đang giao hàng (SHIPPING, DELIVERING)
    private Long completed;         // Hoàn thành (COMPLETED)
    private Long cancelled;         // Đã hủy (CANCELLED)
    private Long failed;            // Thất bại/Hoàn trả (DELIVERY_FAILED, RETURNING, RETURNED)
    private Long lost;              // Mất hàng (LOST)
}
