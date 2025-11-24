package com.greenloop.order.util;

import java.util.Map;


public class ShippingStatusMapper {

    private static final Map<Integer, String> STATUS_MAP = Map.ofEntries(
            Map.entry(900, "Đơn mới"),
            Map.entry(901, "Chờ lấy hàng"),
            Map.entry(902, "Shipper đang qua lấy hàng"),
            Map.entry(903, "Đã lấy hàng"),
            Map.entry(904, "Đang giao hàng"),
            Map.entry(905, "Giao hàng thành công"),
            Map.entry(906, "Giao hàng thất bại"),
            Map.entry(907, "Đang chuyển hoàn"),
            Map.entry(908, "Đã chuyển hoàn"),
            Map.entry(909, "Đã đối soát"),
            Map.entry(910, "Đã đối soát khách"),
            Map.entry(911, "Đã trả COD cho khách"),
            Map.entry(912, "Chờ thanh toán COD"),
            Map.entry(913, "Hoàn thành"),
            Map.entry(914, "Đơn hủy"),
            Map.entry(915, "Chậm lấy/giao"),
            Map.entry(916, "Giao hàng một phần"),
            Map.entry(917, "Thất lạc hàng"),
            Map.entry(918, "Đang lưu kho"),
            Map.entry(919, "Đang vận chuyển"),
            Map.entry(1000, "Đơn lỗi")
    );

    public static String getStatusText(Integer statusCode) {
        if (statusCode == null) {
            return "Chưa có thông tin vận chuyển";
        }
        return STATUS_MAP.getOrDefault(statusCode, "Không xác định");
    }
}
