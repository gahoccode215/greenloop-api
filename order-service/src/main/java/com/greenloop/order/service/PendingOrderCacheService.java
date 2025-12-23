package com.greenloop.order.service;

import com.greenloop.order.dto.redis.PendingOrderRedis;

public interface PendingOrderCacheService {
    void savePendingOrder(PendingOrderRedis pendingOrder);
    PendingOrderRedis getPendingOrder(String orderId);
    String findOrderIdByPaymentCode(Long paymentOrderCode);
    void deletePendingOrder(String orderId, Long paymentOrderCode);
}
