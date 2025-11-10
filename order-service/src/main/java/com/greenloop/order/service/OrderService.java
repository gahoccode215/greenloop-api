package com.greenloop.order.service;

import com.greenloop.order.dto.OrderDTO;
import com.greenloop.order.entity.Order;

import java.util.Optional;

public interface OrderService {
    void createOrder(Order order);
    void updateOrderStatus(String orderId, String newStatus);
    Optional<OrderDTO> fetchOrder(String orderId);
}
