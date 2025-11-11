package com.greenloop.order.enums;

public enum OrderStatus {
    PENDING("Chờ xử lý"),
    CONFIRMED("Đã xác nhận"),
    PROCESSING("Đang xử lý"),
    SHIPPED("Đã giao vận chuyển"),
    DELIVERED("Đã giao hàng"),
    DONE("Hoàn thành"),
    CANCELLED("Đã hủy");

    private final String description;

    OrderStatus(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    /**
     * Kiểm tra trạng thái có thể chuyển đổi không
     */
    public boolean canTransitionTo(OrderStatus newStatus) {
        switch (this) {
            case PENDING:
                return newStatus == CONFIRMED || newStatus == CANCELLED;

            case CONFIRMED:
                return newStatus == PROCESSING || newStatus == DONE || newStatus == CANCELLED;

            case PROCESSING:
                return newStatus == SHIPPED || newStatus == DONE || newStatus == CANCELLED;

            case SHIPPED:
                return newStatus == DELIVERED || newStatus == CANCELLED;

            case DELIVERED:
                return newStatus == DONE;

            case DONE:
            case CANCELLED:
                return false; // Trạng thái cuối, không thể chuyển tiếp

            default:
                return false;
        }
    }
}
