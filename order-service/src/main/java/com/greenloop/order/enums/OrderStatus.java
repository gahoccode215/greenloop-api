package com.greenloop.order.enums;

public enum OrderStatus {
    PENDING("Chờ xử lý"),
    CONFIRMED("Đã xác nhận"),
    PROCESSING("Đang xử lý"),
    READY_TO_SHIP("Chờ lấy hàng"),

    SHIPPING("Đã lấy hàng"),             // GoShip status 903
    DELIVERING("Đang giao hàng"),            // GoShip status 904

    DELIVERED("Đã giao hàng"),               // GoShip status 905
    COMPLETED("Hoàn thành"),                 // Đã đối soát, kết thúc

    DELIVERY_FAILED("Giao thất bại"),        // GoShip status 906
    RETURNING("Đang hoàn trả"),              // GoShip status 907
    RETURNED("Đã hoàn trả"),                 // GoShip status 908

    CANCELLED("Đã hủy"),                     // Customer/Staff hủy hoặc GoShip 914
    LOST("Thất lạc");                        // GoShip status 917

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


    public boolean isCancellable() {
        return this == PENDING || this == CONFIRMED;
    }


}
