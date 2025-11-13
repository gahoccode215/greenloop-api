//package com.greenloop.order.ghn.service;
//
//import com.greenloop.order.command.UpdateOrderStatusCommand;
//import com.greenloop.order.entity.Order;
//import com.greenloop.order.enums.OrderStatus;
//import com.greenloop.order.ghn.client.GHNClient;
//import com.greenloop.order.ghn.dto.response.GHNTrackingResponse;
//import com.greenloop.order.ghn.mapper.GHNStatusMapper;
//import com.greenloop.order.repository.OrderRepository;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//import org.axonframework.commandhandling.gateway.CommandGateway;
//import org.springframework.scheduling.annotation.Scheduled;
//import org.springframework.stereotype.Service;
//
//import java.util.List;
//
//@Service
//@RequiredArgsConstructor
//@Slf4j
//public class GHNPollingService {
//
//    private final OrderRepository orderRepository;
//    private final GHNClient ghnClient;
//    private final CommandGateway commandGateway;
//
//    /**
//     * Tự động check trạng thái đơn hàng từ GHN
//     * Chỉ check các đơn hàng đang trong quá trình vận chuyển
//     */
//    @Scheduled(fixedDelay = 10000) // 10s
//    public void pollOrderStatus() {
//        log.info("=== Starting GHN order status polling ===");
//
//        try {
//            // Lấy các đơn hàng đang shipping (PROCESSING, SHIPPED, DELIVERED)
//            List<Order> shippingOrders = orderRepository.findByOrderStatusIn(
//                    List.of(OrderStatus.PROCESSING, OrderStatus.SHIPPED, OrderStatus.DELIVERED)
//            );
//
//            log.info("Found {} orders to check", shippingOrders.size());
//
//            int updatedCount = 0;
//
//            for (Order order : shippingOrders) {
//                if (order.getGhnOrderCode() != null && !order.getGhnOrderCode().isEmpty()) {
//                    try {
//                        // Gọi GHN API tracking
//                        GHNTrackingResponse tracking = ghnClient.trackOrder(order.getGhnOrderCode());
//
//                        if (tracking != null) {
//                            // Check nếu trạng thái GHN thay đổi
//                            if (!tracking.getStatus().equals(order.getShippingStatus())) {
//                                log.info("Order {} shipping status changed: {} → {}",
//                                        order.getOrderCode(),
//                                        order.getShippingStatus(),
//                                        tracking.getStatus());
//
//                                // Update shipping status
//                                order.setShippingStatus(tracking.getStatus());
//                                orderRepository.save(order);
//
//                                // Map GHN status → OrderStatus
//                                OrderStatus newOrderStatus = GHNStatusMapper.mapToOrderStatus(tracking.getStatus());
//
//                                // Update order status nếu cần
//                                if (newOrderStatus != null && newOrderStatus != order.getOrderStatus()) {
//                                    log.info("Auto updating order {} status: {} → {}",
//                                            order.getOrderCode(),
//                                            order.getOrderStatus(),
//                                            newOrderStatus);
//
//                                    UpdateOrderStatusCommand command = UpdateOrderStatusCommand.builder()
//                                            .orderId(order.getOrderId())
//                                            .orderStatus(newOrderStatus)
//                                            .isSystemUpdate(true)  // Skip validation
//                                            .build();
//
//                                    commandGateway.send(command);
//                                    updatedCount++;
//                                }
//                            }
//                        }
//
//                    } catch (Exception e) {
//                        log.error("Failed to poll order {}", order.getOrderCode(), e);
//                    }
//                }
//            }
//
//            log.info("=== Polling completed: checked {} orders, updated {} orders ===",
//                    shippingOrders.size(), updatedCount);
//
//        } catch (Exception e) {
//            log.error("Polling service error", e);
//        }
//    }
//}
