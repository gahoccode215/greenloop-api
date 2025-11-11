package com.greenloop.order.ghn.service;


import com.greenloop.order.ghn.dto.response.ShippingOrderResponse;

public interface GHNService {
    ShippingOrderResponse createShippingOrder(String orderId);
    String trackOrder(String ghnOrderCode);
    void cancelOrder(String ghnOrderCode);
}
