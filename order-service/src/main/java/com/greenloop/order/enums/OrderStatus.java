package com.greenloop.order.enums;

public enum OrderStatus {
    PENDING("Chờ xử lý"),
    CONFIRMED("Đã xác nhận"),
    PROCESSING("Đang xử lý"),
    READY_TO_SHIP("Chờ lấy hàng"),
    SHIPPING("Đã lấy hàng"),
    DELIVERING("Đang giao hàng"),
    DELIVERED("Đã giao hàng"),
    COMPLETED("Hoàn thành"),
    DELIVERY_FAILED("Giao thất bại"),
    RETURNING("Đang hoàn trả"),
    RETURNED("Đã hoàn trả"),
    CANCELLED("Đã hủy"),
    LOST("Thất lạc");

    private final String description;

    OrderStatus(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    public boolean canTransitionTo(OrderStatus newStatus) {
        return switch (this) {
            case PENDING ->  newStatus == CONFIRMED
                    || newStatus == CANCELLED;

            case CONFIRMED -> newStatus == PROCESSING
                    || newStatus == CANCELLED;

            case PROCESSING -> newStatus == READY_TO_SHIP
                    || newStatus == CANCELLED;

            case READY_TO_SHIP -> newStatus == SHIPPING
                    || newStatus == CANCELLED;

            case SHIPPING -> newStatus == DELIVERING
                    || newStatus == DELIVERED
                    || newStatus == DELIVERY_FAILED
                    || newStatus == LOST;

            case DELIVERING -> newStatus == DELIVERED
                    || newStatus == DELIVERY_FAILED;

            case DELIVERED -> newStatus == COMPLETED
                    || newStatus == RETURNING;

            case DELIVERY_FAILED -> newStatus == SHIPPING
                    || newStatus == RETURNING;

            case RETURNING -> newStatus == RETURNED;

            case COMPLETED, RETURNED, CANCELLED, LOST -> false;
        };
    }

}
