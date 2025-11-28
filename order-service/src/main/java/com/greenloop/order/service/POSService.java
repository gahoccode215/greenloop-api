package com.greenloop.order.service;

import com.greenloop.order.dto.request.order.offline.CreatePOSOrderRequest;
import com.greenloop.order.dto.response.order.offline.POSOrderResponse;

public interface POSService {

    /**
     * Tạo đơn hàng offline tại sự kiện
     * Hỗ trợ thanh toán: CASH, ECO_POINT, MIXED
     */
    POSOrderResponse createPOSOrder(CreatePOSOrderRequest request);

    /**
     * Lấy chi tiết đơn hàng POS
     */
    POSOrderResponse getPOSOrderById(String orderId);
}
