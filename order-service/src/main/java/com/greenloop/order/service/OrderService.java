package com.greenloop.order.service;

import com.greenloop.order.dto.OrderDTO;
import com.greenloop.order.dto.request.CheckoutRequest;
import com.greenloop.order.dto.response.CheckoutResponse;
import com.greenloop.order.entity.Order;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.PaymentStatus;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.Optional;

public interface OrderService {
    void createOrder(Order order);
    void updateOrderStatus(String orderId, OrderStatus newStatus);
    Optional<OrderDTO> fetchOrder(String orderId);
    CheckoutResponse checkout(Long userId, CheckoutRequest request);
    String findOrderIdByPaymentOrderCode(Long paymentOrderCode);
    void updatePaymentStatus(String orderId, PaymentStatus status);
    void updatePaymentTransactionId(String orderId, String transactionId);

    void updateShippingInfo(String orderId, String shipmentId, String trackingCode,
                            String carrier, BigDecimal shippingFee, LocalDateTime expectedDeliveryTime);
    void updateShippingStatus(String orderId, String shippingStatus);
    Optional<Order> findById(String orderId);
}
