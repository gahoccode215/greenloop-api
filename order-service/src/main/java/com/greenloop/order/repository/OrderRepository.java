package com.greenloop.order.repository;

import com.greenloop.order.entity.Order;
import com.greenloop.order.enums.OrderStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface OrderRepository extends JpaRepository<Order, String> {
    Optional<Order> findByOrderCode(String orderCode);
    Optional<Order> findByGhnOrderCode(String ghnOrderCode);
    List<Order> findByOrderStatusIn(List<OrderStatus> statuses);
}
