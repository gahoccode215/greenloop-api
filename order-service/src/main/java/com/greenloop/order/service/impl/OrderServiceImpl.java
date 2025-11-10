package com.greenloop.order.service.impl;

import com.greenloop.order.dto.OrderDTO;
import com.greenloop.order.dto.OrderItemDTO;
import com.greenloop.order.entity.Order;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.repository.OrderRepository;
import com.greenloop.order.service.OrderService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeanUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class OrderServiceImpl implements OrderService {

    private final OrderRepository orderRepository;

    @Override
    @Transactional
    public void createOrder(Order order) {
        orderRepository.save(order);
        log.info("Created order: {}", order.getOrderId());
    }

    @Override
    @Transactional
    public void updateOrderStatus(String orderId, OrderStatus newStatus) {
        orderRepository.findById(orderId).ifPresent(order -> {
            order.setOrderStatus(newStatus);
            orderRepository.save(order);
            log.info("Updated order {} status to {}", orderId, newStatus.getDescription());
        });
    }

    @Override
    public Optional<OrderDTO> fetchOrder(String orderId) {
        return orderRepository.findById(orderId)
                .map(order -> {
                    OrderDTO dto = OrderDTO.builder()
                            .orderId(order.getOrderId())
                            .orderCode(order.getOrderCode())
                            .customerId(order.getCustomerId())
                            .totalPrice(order.getTotalPrice())
                            .orderStatus(order.getOrderStatus())
                            .build();

                    if (order.getOrderItems() != null && !order.getOrderItems().isEmpty()) {
                        List<OrderItemDTO> itemDTOs = order.getOrderItems().stream()
                                .map(item -> OrderItemDTO.builder()
                                        .orderItemId(item.getOrderItemId())
                                        .productId(item.getProductId())
                                        .quantity(item.getQuantity())
                                        .price(item.getPrice())
                                        .build())
                                .collect(Collectors.toList());
                        dto.setOrderItems(itemDTOs);
                    }

                    return dto;
                });
    }

}
