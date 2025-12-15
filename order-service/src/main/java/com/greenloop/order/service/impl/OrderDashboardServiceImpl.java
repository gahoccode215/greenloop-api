package com.greenloop.order.service.impl;

import com.greenloop.order.dto.response.dashboard.*;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.OrderType;
import com.greenloop.order.repository.OrderRepository;
import com.greenloop.order.service.OrderDashboardService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class OrderDashboardServiceImpl implements OrderDashboardService {

    private final OrderRepository orderRepository;

    @Override
    public OrderDashboardOverviewResponse getDashboardOverview() {
        log.info("Fetching order dashboard overview");

        return OrderDashboardOverviewResponse.builder()
                .totalOrders(getTotalOrders())
                .ordersByPeriod(getOrdersByPeriod())
                .revenueStats(getRevenueStats())
                .statusDistribution(getStatusDistribution())
                .ordersByType(getOrdersByType())
                .build();
    }

    // ========== TỔNG QUAN ĐƠN HÀNG ==========

    private Long getTotalOrders() {
        return orderRepository.count();
    }

    private OrdersByPeriod getOrdersByPeriod() {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime startOfToday = LocalDate.now().atStartOfDay();
        LocalDateTime startOfWeek = now.minusDays(7);
        LocalDateTime startOfMonth = now.minusDays(30);

        return OrdersByPeriod.builder()
                .today(orderRepository.countByCreatedAtAfter(startOfToday))
                .thisWeek(orderRepository.countByCreatedAtAfter(startOfWeek))
                .thisMonth(orderRepository.countByCreatedAtAfter(startOfMonth))
                .build();
    }

    // ========== DOANH THU ==========

    private RevenueStats getRevenueStats() {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime startOfToday = LocalDate.now().atStartOfDay();
        LocalDateTime startOfWeek = now.minusDays(7);
        LocalDateTime startOfMonth = now.minusDays(30);

        // Chỉ tính doanh thu từ đơn COMPLETED
        BigDecimal totalRevenue = orderRepository.calculateTotalRevenue(OrderStatus.COMPLETED);
        BigDecimal revenueToday = orderRepository.calculateRevenueAfter(
                OrderStatus.COMPLETED, startOfToday);
        BigDecimal revenueThisWeek = orderRepository.calculateRevenueAfter(
                OrderStatus.COMPLETED, startOfWeek);
        BigDecimal revenueThisMonth = orderRepository.calculateRevenueAfter(
                OrderStatus.COMPLETED, startOfMonth);

        // Tính AOV (Average Order Value)
        Long completedOrders = orderRepository.countByOrderStatus(OrderStatus.COMPLETED);
        BigDecimal averageOrderValue = BigDecimal.ZERO;
        if (completedOrders > 0) {
            averageOrderValue = totalRevenue.divide(
                    BigDecimal.valueOf(completedOrders),
                    2,
                    RoundingMode.HALF_UP
            );
        }

        return RevenueStats.builder()
                .totalRevenue(totalRevenue)
                .revenueToday(revenueToday)
                .revenueThisWeek(revenueThisWeek)
                .revenueThisMonth(revenueThisMonth)
                .averageOrderValue(averageOrderValue)
                .build();
    }

    // ========== PHÂN BỐ THEO TRẠNG THÁI ==========

    private OrderStatusDistribution getStatusDistribution() {
        // Chờ xử lý
        Long pending = orderRepository.countByOrderStatus(OrderStatus.PENDING);

        // Đang xử lý (CONFIRMED, PROCESSING, READY_TO_SHIP)
        Long processing = orderRepository.countByOrderStatusIn(
                Arrays.asList(
                        OrderStatus.CONFIRMED,
                        OrderStatus.PROCESSING,
                        OrderStatus.READY_TO_SHIP
                )
        );

        // Đang giao hàng (SHIPPING, DELIVERING)
        Long shipping = orderRepository.countByOrderStatusIn(
                Arrays.asList(
                        OrderStatus.SHIPPING,
                        OrderStatus.DELIVERING
                )
        );

        // Hoàn thành
        Long completed = orderRepository.countByOrderStatus(OrderStatus.COMPLETED);

        // Đã hủy
        Long cancelled = orderRepository.countByOrderStatus(OrderStatus.CANCELLED);

        // Thất bại/Hoàn trả (DELIVERY_FAILED, RETURNING, RETURNED)
        Long failed = orderRepository.countByOrderStatusIn(
                Arrays.asList(
                        OrderStatus.DELIVERY_FAILED,
                        OrderStatus.RETURNING,
                        OrderStatus.RETURNED
                )
        );

        // Mất hàng
        Long lost = orderRepository.countByOrderStatus(OrderStatus.LOST);

        return OrderStatusDistribution.builder()
                .pending(pending)
                .processing(processing)
                .shipping(shipping)
                .completed(completed)
                .cancelled(cancelled)
                .failed(failed)
                .lost(lost)
                .build();
    }

    // ========== PHÂN BỐ THEO LOẠI ĐƠN ==========

    private Map<String, Long> getOrdersByType() {
        List<Object[]> results = orderRepository.countOrdersByType();

        Map<String, Long> typeMap = results.stream()
                .collect(Collectors.toMap(
                        row -> ((OrderType) row[0]).name(),
                        row -> (Long) row[1]
                ));

        // Đảm bảo có đủ 2 loại
        typeMap.putIfAbsent("ONLINE", 0L);
        typeMap.putIfAbsent("OFFLINE", 0L);

        return typeMap;
    }
}
