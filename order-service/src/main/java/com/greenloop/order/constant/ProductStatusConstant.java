package com.greenloop.order.constant;

public class ProductStatusConstant {
    public static final String IN_EVENT = "IN_EVENT";           // Bán tại event
    public static final String AVAILABLE = "AVAILABLE";         // Có thể mua online
    public static final String RESERVED = "RESERVED";           // Đã checkout
    public static final String READY_TO_SHIP = "READY_TO_SHIP"; // Staff đã tạo vận đơn
    public static final String IN_TRANSIT = "IN_TRANSIT";       // GoShip đã lấy hàng
    public static final String SOLD = "SOLD";                   // Giao thành công
    public static final String LOST = "LOST";                   // Mất trong vận chuyển
}
