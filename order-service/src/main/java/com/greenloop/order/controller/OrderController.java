package com.greenloop.order.controller;

import com.greenloop.order.dto.request.CreateShipmentRequestDTO;
import com.greenloop.order.dto.request.OrderFilterRequest;
import com.greenloop.order.dto.request.UpdateOrderStatusRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.OrderHistoryResponse;
import com.greenloop.order.dto.response.OrderResponse;
import com.greenloop.order.dto.response.PageResponseDTO;
import com.greenloop.order.dto.response.ShipmentInfoResponse;
import com.greenloop.order.entity.Order;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.PaymentStatus;
import com.greenloop.order.exception.OrderAccessDeniedException;
import com.greenloop.order.goship.dto.CreateShipmentResponse;
import com.greenloop.order.goship.service.GoShipService;
import com.greenloop.order.service.OrderHistoryService;
import com.greenloop.order.service.OrderService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/orders")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Order Management", description = "Order management APIs")
public class OrderController {

    private final OrderService orderService;
    private final OrderHistoryService orderHistoryService;
    private final GoShipService goShipService;


    @Operation(summary = "Get all orders", description = "Admin/Manager can view all orders with filters")
    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public ResponseEntity<ApiResponseDTO<PageResponseDTO<OrderResponse>>> getAllOrders(
            @RequestParam(defaultValue = "0") Integer page,
            @RequestParam(defaultValue = "10") Integer size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "DESC") String sortDirection,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String paymentStatus,
            @RequestParam(required = false) String searchKeyword,
            @RequestParam(required = false) Long customerId,
            @RequestParam(required = false) String fromDate,
            @RequestParam(required = false) String toDate) {

        OrderFilterRequest filter = buildFilter(page, size, sortBy, sortDirection,
                status, paymentStatus, searchKeyword, fromDate, toDate);
        filter.setCustomerId(customerId);

        PageResponseDTO<OrderResponse> response = orderService.getAllOrders(null, filter);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy danh sách đơn hàng thành công",
                        response,
                        HttpStatus.OK
                )
        );
    }

    @Operation(summary = "Get order detail by ID", description = "Admin/Manager can view any order detail")
    @GetMapping("/{orderId}")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public ResponseEntity<ApiResponseDTO<OrderResponse>> getOrderDetail(
            @PathVariable String orderId) {

        OrderResponse response = orderService.getOrderById(orderId);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy thông tin đơn hàng thành công",
                        response,
                        HttpStatus.OK
                )
        );
    }

    @Operation(summary = "Get my orders", description = "Customer can view their own orders")
    @GetMapping("/my-orders")
    @PreAuthorize("hasRole('CUSTOMER')")
    public ResponseEntity<ApiResponseDTO<PageResponseDTO<OrderResponse>>> getMyOrders(
            @RequestParam(defaultValue = "0") Integer page,
            @RequestParam(defaultValue = "10") Integer size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "DESC") String sortDirection,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String paymentStatus,
            @RequestParam(required = false) String searchKeyword,
            @RequestParam(required = false) String fromDate,
            @RequestParam(required = false) String toDate) {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long userId = Long.valueOf(auth.getName());

        log.info("Customer {} fetching their orders", userId);

        OrderFilterRequest filter = buildFilter(page, size, sortBy, sortDirection,
                status, paymentStatus, searchKeyword, fromDate, toDate);

        PageResponseDTO<OrderResponse> response = orderService.getAllOrders(userId, filter);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy danh sách đơn hàng thành công",
                        response,
                        HttpStatus.OK
                )
        );
    }

    @Operation(summary = "Get my order detail", description = "Customer can view their own order detail")
    @GetMapping("/my-orders/{orderId}")
    @PreAuthorize("hasRole('CUSTOMER')")
    public ResponseEntity<ApiResponseDTO<OrderResponse>> getMyOrderDetail(
            @PathVariable String orderId) {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long userId = Long.valueOf(auth.getName());

        log.info("Customer {} fetching order detail: {}", userId, orderId);

        OrderResponse response = orderService.getOrderById(orderId);

        if (!response.getCustomerId().equals(userId)) {
            throw new OrderAccessDeniedException(orderId, userId);
        }

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy thông tin đơn hàng thành công",
                        response,
                        HttpStatus.OK
                )
        );
    }

    @Operation(summary = "Get order history", description = "View order status change timeline")
    @GetMapping("/{orderId}/history")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponseDTO<List<OrderHistoryResponse>>> getOrderHistory(
            @PathVariable String orderId) {

        log.info("Fetching order history for orderId: {}", orderId);

        List<OrderHistoryResponse> history = orderHistoryService.getOrderHistory(orderId);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy lịch sử đơn hàng thành công",
                        history,
                        HttpStatus.OK
                )
        );
    }


    @Operation(summary = "Confirm order", description = "Staff/Admin/Manager confirm order")
    @PostMapping("/{orderId}/confirm")
    @PreAuthorize("hasAnyRole('STAFF', 'ADMIN', 'MANAGER')")
    public ResponseEntity<ApiResponseDTO<Void>> confirmOrder(
            @PathVariable String orderId,
            @RequestParam(required = false) String reason) {

        UpdateOrderStatusRequest request = UpdateOrderStatusRequest.builder()
                .newStatus(OrderStatus.CONFIRMED)
                .reason(reason)
                .build();

        orderService.updateOrderStatusWithDetails(orderId, request);

        return ResponseEntity.ok(
                ApiResponseDTO.success("Xác nhận đơn hàng thành công", null, HttpStatus.OK)
        );
    }

    @Operation(summary = "Process order", description = "Staff/Admin/Manager start processing order")
    @PostMapping("/{orderId}/process")
    @PreAuthorize("hasAnyRole('STAFF', 'ADMIN', 'MANAGER')")
    public ResponseEntity<ApiResponseDTO<Void>> processOrder(
            @PathVariable String orderId,
            @RequestParam(required = false) String reason) {

        UpdateOrderStatusRequest request = UpdateOrderStatusRequest.builder()
                .newStatus(OrderStatus.PROCESSING)
                .reason(reason)
                .build();

        orderService.updateOrderStatusWithDetails(orderId, request);

        return ResponseEntity.ok(
                ApiResponseDTO.success("Bắt đầu xử lý đơn hàng thành công", null, HttpStatus.OK)
        );
    }

    @Operation(summary = "Ship order", description = "Create shipment and mark order ready to ship")
    @PostMapping("/{orderId}/ship")
    @PreAuthorize("hasAnyRole('STAFF', 'ADMIN', 'MANAGER')")
    public ResponseEntity<ApiResponseDTO<ShipmentInfoResponse>> shipOrder(
            @PathVariable String orderId,
            @Valid @RequestBody CreateShipmentRequestDTO request) {

        CreateShipmentResponse shipmentResponse = goShipService.createShipmentForOrder(orderId, request);

        UpdateOrderStatusRequest statusRequest = UpdateOrderStatusRequest.builder()
                .newStatus(OrderStatus.READY_TO_SHIP)
                .reason(request.getReason())
                .goshipShipmentId(shipmentResponse.getId())
                .goshipTrackingCode(shipmentResponse.getTrackingNumber())
                .carrier(shipmentResponse.getCarrier())
                .build();

        orderService.updateOrderStatusWithDetails(orderId, statusRequest);

        ShipmentInfoResponse response = ShipmentInfoResponse.builder()
                .shipmentId(shipmentResponse.getId())
                .trackingNumber(shipmentResponse.getTrackingNumber())
                .carrier(shipmentResponse.getCarrier())
                .fee(shipmentResponse.getFee())
                .createdAt(shipmentResponse.getCreatedAt())
                .build();

        return ResponseEntity.ok(
                ApiResponseDTO.success("Tạo vận đơn thành công", response, HttpStatus.OK)
        );
    }

    @Operation(summary = "Complete order", description = "Mark order as completed")
    @PostMapping("/{orderId}/complete")
    @PreAuthorize("hasAnyRole('STAFF', 'ADMIN', 'MANAGER')")
    public ResponseEntity<ApiResponseDTO<Void>> completeOrder(
            @PathVariable String orderId,
            @RequestParam(required = false) String reason) {

        UpdateOrderStatusRequest request = UpdateOrderStatusRequest.builder()
                .newStatus(OrderStatus.COMPLETED)
                .reason(reason)
                .build();

        orderService.updateOrderStatusWithDetails(orderId, request);

        return ResponseEntity.ok(
                ApiResponseDTO.success("Hoàn thành đơn hàng thành công", null, HttpStatus.OK)
        );
    }

    @Operation(summary = "Cancel order", description = "Cancel order and shipment if exists")
    @PostMapping("/{orderId}/cancel")
    @PreAuthorize("hasAnyRole('STAFF', 'ADMIN', 'MANAGER', 'CUSTOMER')")
    public ResponseEntity<ApiResponseDTO<Void>> cancelOrder(
            @PathVariable String orderId,
            @RequestParam(required = false) String reason) {

        Order order = orderService.getOrderEntityById(orderId);

        // Cancel shipment if exists
        if (order.getGoshipShipmentId() != null) {
            goShipService.cancelShipment(order.getGoshipShipmentId());
        }

        UpdateOrderStatusRequest request = UpdateOrderStatusRequest.builder()
                .newStatus(OrderStatus.CANCELLED)
                .reason(reason)
                .build();

        orderService.updateOrderStatusWithDetails(orderId, request);

        return ResponseEntity.ok(
                ApiResponseDTO.success("Hủy đơn hàng thành công", null, HttpStatus.OK)
        );
    }


    /**
     * Build OrderFilterRequest from query parameters
     */
    private OrderFilterRequest buildFilter(Integer page, Integer size, String sortBy,
                                           String sortDirection, String status,
                                           String paymentStatus, String searchKeyword,
                                           String fromDate, String toDate) {
        OrderFilterRequest filter = OrderFilterRequest.builder()
                .page(page)
                .size(size)
                .sortBy(sortBy)
                .sortDirection(sortDirection)
                .searchKeyword(searchKeyword)
                .fromDate(fromDate)
                .toDate(toDate)
                .build();

        try {
            if (status != null && !status.trim().isEmpty()) {
                filter.setStatus(OrderStatus.valueOf(status.toUpperCase()));
            }
            if (paymentStatus != null && !paymentStatus.trim().isEmpty()) {
                filter.setPaymentStatus(PaymentStatus.valueOf(paymentStatus.toUpperCase()));
            }
        } catch (IllegalArgumentException e) {
            log.warn("Invalid enum value: {}", e.getMessage());
        }

        return filter;
    }
}
