package com.greenloop.order.query.controller;

import com.greenloop.order.dto.request.OrderFilterRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.OrderHistoryResponse;
import com.greenloop.order.dto.response.OrderResponse;
import com.greenloop.order.dto.response.PageResponseDTO;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.PaymentStatus;
import com.greenloop.order.exception.OrderAccessDeniedException;
import com.greenloop.order.query.GetOrderQuery;
import com.greenloop.order.service.OrderHistoryService;
import com.greenloop.order.service.OrderService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.axonframework.messaging.responsetypes.ResponseTypes;
import org.axonframework.queryhandling.QueryGateway;
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
public class OrderQueryController {

    private final QueryGateway queryGateway;
    private final OrderService orderService;
    private final OrderHistoryService orderHistoryService;

    @Operation(summary = "Get all orders (Admin)")
    @GetMapping
    public ResponseEntity<ApiResponseDTO<PageResponseDTO<OrderResponse>>> getAllOrders(
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") Integer page,

            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "10") Integer size,

            @Parameter(description = "Sort field")
            @RequestParam(defaultValue = "createdAt") String sortBy,

            @Parameter(description = "Sort direction (ASC/DESC)")
            @RequestParam(defaultValue = "DESC") String sortDirection,

            @Parameter(description = "Filter by order status")
            @RequestParam(required = false) String status,

            @Parameter(description = "Filter by payment status")
            @RequestParam(required = false) String paymentStatus,

            @Parameter(description = "Search by orderCode or orderId")
            @RequestParam(required = false) String searchKeyword,

            @Parameter(description = "Filter by customer ID")
            @RequestParam(required = false) Long customerId,

            @Parameter(description = "Filter from date (yyyy-MM-dd)")
            @RequestParam(required = false) String fromDate,

            @Parameter(description = "Filter to date (yyyy-MM-dd)")
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

    @Operation(summary = "Get order detail (Admin)")
    @GetMapping("/{orderId}")
    public ResponseEntity<ApiResponseDTO<OrderResponse>> getOrderDetail(
            @PathVariable String orderId) {

        GetOrderQuery query = new GetOrderQuery(orderId);
        OrderResponse response = queryGateway.query(
                query,
                ResponseTypes.instanceOf(OrderResponse.class)
        ).join();

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy thông tin đơn hàng thành công",
                        response,
                        HttpStatus.OK
                )
        );
    }

    @Operation(summary = "Get my orders (Customer)")
    @GetMapping("/my-orders")
    public ResponseEntity<ApiResponseDTO<PageResponseDTO<OrderResponse>>> getMyOrders(
            @Parameter(description = "Page number (0-based)")
            @RequestParam(defaultValue = "0") Integer page,

            @Parameter(description = "Page size")
            @RequestParam(defaultValue = "10") Integer size,

            @Parameter(description = "Sort field")
            @RequestParam(defaultValue = "createdAt") String sortBy,

            @Parameter(description = "Sort direction (ASC/DESC)")
            @RequestParam(defaultValue = "DESC") String sortDirection,

            @Parameter(description = "Filter by order status")
            @RequestParam(required = false) String status,

            @Parameter(description = "Filter by payment status")
            @RequestParam(required = false) String paymentStatus,

            @Parameter(description = "Search by orderCode or orderId")
            @RequestParam(required = false) String searchKeyword,

            @Parameter(description = "Filter from date (yyyy-MM-dd)")
            @RequestParam(required = false) String fromDate,

            @Parameter(description = "Filter to date (yyyy-MM-dd)")
            @RequestParam(required = false) String toDate) {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long userId = Long.valueOf(auth.getName());

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

    @Operation(summary = "Get my order detail (Customer)")
    @GetMapping("/my-orders/{orderId}")
    public ResponseEntity<ApiResponseDTO<OrderResponse>> getMyOrderDetail(
            @PathVariable String orderId) {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Long userId = Long.valueOf(auth.getName());

        GetOrderQuery query = new GetOrderQuery(orderId);
        OrderResponse response = queryGateway.query(
                query,
                ResponseTypes.instanceOf(OrderResponse.class)
        ).join();

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

    @GetMapping("/{orderId}/history")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Lấy lịch sử đơn hàng", description = "Xem timeline thay đổi trạng thái của đơn hàng")
    public ResponseEntity<ApiResponseDTO<List<OrderHistoryResponse>>> getOrderHistory(
            @PathVariable String orderId) {

        List<OrderHistoryResponse> history = orderHistoryService.getOrderHistory(orderId);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy lịch sử đơn hàng thành công",
                        history,
                        HttpStatus.OK
                )
        );
    }

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
