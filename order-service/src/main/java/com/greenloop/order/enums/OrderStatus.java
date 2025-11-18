package com.greenloop.order.enums;

public enum OrderStatus {
    // Customer flow
    PENDING("Chờ xử lý"),                    // Order mới tạo
    PAYMENT_PENDING("Chờ thanh toán"),       // Đang chờ PayOS callback

    // Staff flow
    CONFIRMED("Đã xác nhận"),                // Staff xác nhận đơn (có thể cancel)
    PROCESSING("Đang đóng gói"),             // Staff đang chuẩn bị hàng
    SHIPPED("Đã giao shipper"),              // ← Đã đóng gói xong, giao cho shipper
    //   **TRIGGER CREATE SHIPMENT TẠI ĐÂY**

    // Shipping flow (from GoShip webhook)
    SHIPPING("Đang vận chuyển"),             // Shipper đang giao (từ GoShip)
    DELIVERING("Đang giao hàng"),            // Shipper đến địa chỉ khách

    // Success flow
    DELIVERED("Đã giao hàng"),               // Khách đã nhận hàng
    COMPLETED("Hoàn thành"),                 // COD đã thu, đơn kết thúc

    // Failure/Return flow
    DELIVERY_FAILED("Giao hàng thất bại"),
    RETURNING("Đang hoàn trả"),
    RETURNED("Đã hoàn trả"),

    // Cancel flow
    CANCELLED("Đã hủy");

    private final String description;

    OrderStatus(String description) {
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    public boolean canTransitionTo(OrderStatus newStatus) {
        switch (this) {
            case PENDING:
                return newStatus == PAYMENT_PENDING
                        || newStatus == CONFIRMED
                        || newStatus == CANCELLED;

            case PAYMENT_PENDING:
                return newStatus == CONFIRMED
                        || newStatus == CANCELLED;

            case CONFIRMED:
                return newStatus == PROCESSING
                        || newStatus == CANCELLED;  // ← Có thể cancel

            case PROCESSING:
                return newStatus == SHIPPED  // ← Đóng gói xong → SHIPPED
                        || newStatus == CANCELLED;

            case SHIPPED:
                return newStatus == SHIPPING  // ← GoShip webhook update
                        || newStatus == CANCELLED;  // Có thể cancel nếu chưa lấy hàng

            case SHIPPING:
                return newStatus == DELIVERING
                        || newStatus == DELIVERY_FAILED
                        || newStatus == CANCELLED;

            case DELIVERING:
                return newStatus == DELIVERED
                        || newStatus == DELIVERY_FAILED;

            case DELIVERED:
                return newStatus == COMPLETED
                        || newStatus == RETURNING;

            case DELIVERY_FAILED:
                return newStatus == SHIPPING  // Retry
                        || newStatus == RETURNING;

            case RETURNING:
                return newStatus == RETURNED;

            case COMPLETED:
            case RETURNED:
            case CANCELLED:
                return false; // Terminal states

            default:
                return false;
        }
    }

    public boolean isCancellable() {
        return this == PENDING
                || this == PAYMENT_PENDING
                || this == CONFIRMED
                || this == PROCESSING
                || this == SHIPPED;  // Có thể cancel nếu shipper chưa lấy
    }
}
