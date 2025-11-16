package com.greenloop.order.service;

import com.greenloop.order.dto.OrderDTO;
import com.greenloop.order.dto.request.CheckoutRequest;
import com.greenloop.order.dto.response.CheckoutResponse;
import com.greenloop.order.entity.Order;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.PaymentStatus;

import java.util.Optional;

public interface OrderService {
    void createOrder(Order order);
    void updateOrderStatus(String orderId, OrderStatus newStatus);
    Optional<OrderDTO> fetchOrder(String orderId);
    CheckoutResponse checkout(Long userId, CheckoutRequest request, String ipAddress);

    String findOrderIdByPaymentOrderCode(Long paymentOrderCode);

    void updatePaymentStatus(String orderId, PaymentStatus status);

    void updatePaymentTransactionId(String orderId, String transactionId);

}
