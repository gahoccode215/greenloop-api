package com.greenloop.order.repository;

import com.greenloop.order.entity.Order;
import com.greenloop.order.enums.OrderStatus;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface OrderRepository extends JpaRepository<Order, String> {
    Optional<Order> findByOrderCode(String orderCode);
    Optional<Order> findByPaymentOrderCode(Long paymentOrderCode);

    Optional<Order> findByGoshipShipmentId(String goshipShipmentId);
    Optional<Order> findByGoshipTrackingCode(String goshipTrackingCode);

}
