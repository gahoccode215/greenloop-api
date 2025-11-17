package com.greenloop.order.goship.service;

import com.greenloop.order.goship.dto.*;
import com.greenloop.order.entity.Order;

import java.util.List;

public interface GoShipService {

    /**
     * Tính phí vận chuyển từ nhiều đơn vị vận chuyển
     */
    List<RateResponse> calculateShippingRates(CalculateRateRequest request);

    /**
     * Tạo đơn giao hàng trên GoShip
     */
    ShipmentResponse createShipment(Order order);

    /**
     * Lấy thông tin chi tiết shipment
     */
    ShipmentResponse getShipment(String shipmentId);

}
