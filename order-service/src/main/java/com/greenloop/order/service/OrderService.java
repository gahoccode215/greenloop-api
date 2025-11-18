package com.greenloop.order.service;

import com.greenloop.order.dto.OrderDTO;
import com.greenloop.order.dto.request.CheckoutRequest;
import com.greenloop.order.dto.request.OrderFilterRequest;
import com.greenloop.order.dto.response.CheckoutResponse;
import com.greenloop.order.dto.response.OrderResponse;
import com.greenloop.order.dto.response.PageResponseDTO;
import com.greenloop.order.entity.Order;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.PaymentStatus;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.Optional;

public interface OrderService {
    void createOrder(Order order);
    void updateOrderStatus(String orderId, OrderStatus newStatus);
    CheckoutResponse checkout(Long userId, CheckoutRequest request);
    String findOrderIdByPaymentOrderCode(Long paymentOrderCode);
    void updatePaymentStatus(String orderId, PaymentStatus status);
    void updatePaymentTransactionId(String orderId, String transactionId);

    OrderResponse getOrderById(String orderId);
    PageResponseDTO<OrderResponse> getAllOrders(Long requestingUserId, OrderFilterRequest filter);

}
