package com.greenloop.order.repository;

import com.greenloop.order.entity.Order;
import com.greenloop.order.enums.OrderStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.math.BigDecimal;
import java.time.LocalDateTime;
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


    // ========== TỔNG QUAN ĐƠN HÀNG ==========

    // Tổng số đơn hàng
    long count();

    // Đơn hàng theo khoảng thời gian
    long countByCreatedAtAfter(LocalDateTime startDate);

    long countByCreatedAtBetween(LocalDateTime startDate, LocalDateTime endDate);

    // ========== DOANH THU ==========

    // Tổng doanh thu (chỉ tính đơn COMPLETED)
    @Query("SELECT COALESCE(SUM(o.totalPrice), 0) FROM Order o WHERE o.orderStatus = :status")
    BigDecimal calculateTotalRevenue(@Param("status") OrderStatus status);

    // Doanh thu theo khoảng thời gian
    @Query("SELECT COALESCE(SUM(o.totalPrice), 0) FROM Order o " +
            "WHERE o.orderStatus = :status AND o.createdAt >= :startDate")
    BigDecimal calculateRevenueAfter(
            @Param("status") OrderStatus status,
            @Param("startDate") LocalDateTime startDate);

    @Query("SELECT COALESCE(SUM(o.totalPrice), 0) FROM Order o " +
            "WHERE o.orderStatus = :status " +
            "AND o.createdAt BETWEEN :startDate AND :endDate")
    BigDecimal calculateRevenueBetween(
            @Param("status") OrderStatus status,
            @Param("startDate") LocalDateTime startDate,
            @Param("endDate") LocalDateTime endDate);

    // ========== PHÂN BỐ THEO TRẠNG THÁI ==========

    // Đếm theo trạng thái cụ thể
    long countByOrderStatus(OrderStatus status);

    // Đếm theo nhiều trạng thái
    long countByOrderStatusIn(List<OrderStatus> statuses);

    // ========== PHÂN BỐ THEO LOẠI ĐƠN ==========

    @Query("SELECT o.orderType, COUNT(o) FROM Order o GROUP BY o.orderType")
    List<Object[]> countOrdersByType();
}
