package com.greenloop.order.service.impl;

import com.greenloop.order.dto.redis.PendingOrderRedis;
import com.greenloop.order.service.PendingOrderCacheService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class PendingOrderCacheServiceImpl implements PendingOrderCacheService {

    private final RedisTemplate<String, Object> redisTemplate;

    @Value("${order.redis.pending-order-ttl:900}")
    private Long pendingOrderTtl;

    private static final String PENDING_ORDER_KEY_PREFIX = "pending_order:";
    private static final String PAYMENT_CODE_MAPPING_PREFIX = "payment_code_mapping:";

    @Override
    public void savePendingOrder(PendingOrderRedis pendingOrder) {
        String key = buildOrderKey(pendingOrder.getOrderId());

        try {
            redisTemplate.opsForValue().set(
                    key,
                    pendingOrder,
                    pendingOrderTtl,
                    TimeUnit.SECONDS
            );

            if (pendingOrder.getPaymentOrderCode() != null) {
                String mappingKey = buildPaymentCodeMappingKey(
                        pendingOrder.getPaymentOrderCode());

                redisTemplate.opsForValue().set(
                        mappingKey,
                        pendingOrder.getOrderId(),
                        pendingOrderTtl,
                        TimeUnit.SECONDS
                );
            }

            log.info("Saved pending order to Redis: {} (TTL: {}s)",
                    pendingOrder.getOrderCode(), pendingOrderTtl);

        } catch (Exception e) {
            log.error("Failed to save pending order to Redis: {}",
                    pendingOrder.getOrderId(), e);
            throw new RuntimeException("Không thể lưu đơn hàng vào cache", e);
        }
    }

    @Override
    public PendingOrderRedis getPendingOrder(String orderId) {
        String key = buildOrderKey(orderId);

        try {
            Object value = redisTemplate.opsForValue().get(key);

            if (value != null) {
                log.info("Retrieved pending order from Redis: {}", orderId);
                return (PendingOrderRedis) value;
            }

            log.warn("Pending order not found in Redis: {}", orderId);
            return null;

        } catch (Exception e) {
            log.error("Failed to get pending order from Redis: {}", orderId, e);
            return null;
        }
    }

    @Override
    public String findOrderIdByPaymentCode(Long paymentOrderCode) {
        String key = buildPaymentCodeMappingKey(paymentOrderCode);

        try {
            Object value = redisTemplate.opsForValue().get(key);

            if (value != null) {
                return (String) value;
            }

            log.warn("OrderId not found for paymentOrderCode: {}", paymentOrderCode);
            return null;

        } catch (Exception e) {
            log.error("Failed to find orderId from Redis: {}", paymentOrderCode, e);
            return null;
        }
    }

    @Override
    public void deletePendingOrder(String orderId, Long paymentOrderCode) {
        try {
            String orderKey = buildOrderKey(orderId);
            redisTemplate.delete(orderKey);

            if (paymentOrderCode != null) {
                String mappingKey = buildPaymentCodeMappingKey(paymentOrderCode);
                redisTemplate.delete(mappingKey);
            }

            log.info("Deleted pending order from Redis: {}", orderId);

        } catch (Exception e) {
            log.error("Failed to delete pending order from Redis: {}", orderId, e);
        }
    }

    private String buildOrderKey(String orderId) {
        return PENDING_ORDER_KEY_PREFIX + orderId;
    }

    private String buildPaymentCodeMappingKey(Long paymentOrderCode) {
        return PAYMENT_CODE_MAPPING_PREFIX + paymentOrderCode;
    }
}
