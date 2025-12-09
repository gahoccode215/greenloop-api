package com.greenloop.order.service;

import com.greenloop.order.dto.request.*;
import com.greenloop.order.dto.response.CheckoutResponse;
import com.greenloop.order.dto.response.OrderResponse;
import com.greenloop.order.dto.response.PageResponseDTO;
import com.greenloop.order.dto.response.ShipmentInfoResponse;
import com.greenloop.order.entity.Order;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.PaymentStatus;



public interface OrderService {
    void updateOrderStatus(String orderId, OrderStatus newStatus);
    CheckoutResponse checkout(Long userId, CheckoutRequest request);
    String findOrderIdByPaymentOrderCode(Long paymentOrderCode);
    void updatePaymentStatus(String orderId, PaymentStatus status);
    void updatePaymentTransactionId(String orderId, String transactionId);
    Order getOrderEntityById(String orderId);
    OrderResponse getOrderById(String orderId);
    PageResponseDTO<OrderResponse> getAllOrders(Long requestingUserId, OrderFilterRequest filter);
    void cancelOrder(String orderId, String reason, Long requestingUserId, String userRole);;
    void confirmOrder(String orderId, String reason);
    void processOrder(String orderId, String reason);
    void completeOrder(String orderId, String reason);
    ShipmentInfoResponse shipOrder(String orderId, CreateShipmentRequestDTO request);
    Order buildAndSaveOrder(CreateOrderRequest request);
    void handleLostOrder(String orderId, String reason);
}
