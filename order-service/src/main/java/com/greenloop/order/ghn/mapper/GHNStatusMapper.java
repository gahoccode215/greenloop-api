package com.greenloop.order.ghn.mapper;

import com.greenloop.order.enums.OrderStatus;

public class GHNStatusMapper {

    /**
     * Map GHN shipping status sang OrderStatus của hệ thống
     */
    public static OrderStatus mapToOrderStatus(String ghnStatus) {
        if (ghnStatus == null) {
            return null;
        }

        return switch (ghnStatus.toLowerCase()) {
            // Đang chuẩn bị/lấy hàng → PROCESSING
            case "ready_to_pick", "picking", "picked", "money_collect_picking" ->
                    OrderStatus.PROCESSING;

            // Đang vận chuyển → SHIPPED
            case "storing", "transporting", "sorting" ->
                    OrderStatus.SHIPPED;

            // Đang giao hàng → DELIVERED
            case "delivering" ->
                    OrderStatus.DELIVERED;

            // Giao thành công → DONE
            case "delivered" ->
                    OrderStatus.DONE;

            // Hủy/Trả hàng → CANCELLED
            case "cancel", "returned", "return", "exception", "damage" ->
                    OrderStatus.CANCELLED;

            default -> null;  // Không map được thì giữ nguyên
        };
    }
}
