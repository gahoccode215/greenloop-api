package com.greenloop.order.util;

import com.greenloop.order.enums.OrderStatus;
import lombok.extern.slf4j.Slf4j;


@Slf4j
public class OrderStatusSyncMapper {

    public static OrderStatus getTargetOrderStatus(Integer goshipStatusCode, OrderStatus currentOrderStatus) {
        if (goshipStatusCode == null) {
            return null;
        }

        OrderStatus targetStatus = switch (goshipStatusCode) {
            // 900-902: Chưa/đang lấy hàng → Không thay đổi (đã READY_TO_SHIP rồi)
            case 900, 901, 902 -> null;

            // 903: Đã lấy hàng → SHIPPING
            case 903 -> OrderStatus.SHIPPING;

            // 919: Đang vận chuyển → SHIPPING
            case 919 -> OrderStatus.SHIPPING;

            // 904: Đang giao hàng → DELIVERING
            case 904 -> OrderStatus.DELIVERING;

            // 905: Giao thành công → DELIVERED
            case 905 -> OrderStatus.DELIVERED;

            // 906: Giao thất bại → DELIVERY_FAILED
            case 906 -> OrderStatus.DELIVERY_FAILED;

            // 907: Đang chuyển hoàn → RETURNING
            case 907 -> OrderStatus.RETURNING;

            // 908: Đã hoàn trả → RETURNED
            case 908 -> OrderStatus.RETURNED;

            case 913 -> null;  // Manual complete sau khi đối soát

            // 914: Hủy → CANCELLED
            case 914 -> OrderStatus.CANCELLED;

            // 917: Thất lạc → LOST
            case 917 -> OrderStatus.LOST;

            // 909-912: Đối soát, trả COD → Không ánh xạ
            // 915: Chậm lấy/giao → Không ánh xạ
            // 916: Giao một phần → Không ánh xạ
            // 918: Lưu kho → Không ánh xạ
            // 1000: Đơn lỗi → Không ánh xạ
            default -> null;
        };
        if (targetStatus != null && !currentOrderStatus.canTransitionTo(targetStatus)) {
            return null;
        }
        return targetStatus;
    }
}

