package com.greenloop.order.repository;

import com.greenloop.order.entity.Order;
import com.greenloop.order.enums.OrderStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface OrderRepository extends JpaRepository<Order, String> , JpaSpecificationExecutor<Order> {
    Optional<Order> findByPaymentOrderCode(Long paymentOrderCode);
    long countByOrderCodeStartingWith(String prefix);
    @Query("SELECT o FROM Order o " +
            "WHERE o.orderStatus IN :statuses " +
            "AND o.goshipShipmentId IS NOT NULL " +
            "ORDER BY o.createdAt DESC")
    List<Order> findActiveShipments(@Param("statuses") List<OrderStatus> statuses);
}
