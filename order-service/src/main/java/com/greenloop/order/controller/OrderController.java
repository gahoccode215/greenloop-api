package com.greenloop.order.controller;

import com.greenloop.order.dto.request.CreateShipmentRequestDTO;
import com.greenloop.order.dto.request.OrderFilterRequest;
import com.greenloop.order.dto.request.UpdateOrderStatusRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.OrderResponse;
import com.greenloop.order.dto.response.PageResponseDTO;
import com.greenloop.order.dto.response.ShipmentInfoResponse;
import com.greenloop.order.entity.Order;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.OrderType;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import com.greenloop.order.exception.OrderAccessDeniedException;
import com.greenloop.order.goship.dto.CreateShipmentResponse;
import com.greenloop.order.goship.service.GoShipService;
import com.greenloop.order.service.OrderService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;

@RestController
@RequestMapping("/api/v1/orders")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Order Management", description = "Order management APIs")
public class OrderController {

    private final OrderService orderService;

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF')")
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
            @RequestParam(required = false) String toDate,
            @RequestParam(required = false) String orderType,
            @RequestParam(required = false) Long eventId,
            @RequestParam(required = false) Boolean isGuestPurchase,
            @RequestParam(required = false) String paymentMethod,
            @RequestParam(required = false) String createdBy,
            @RequestParam(required = false) BigDecimal minPrice,
            @RequestParam(required = false) BigDecimal maxPrice) {

        OrderFilterRequest filter = buildFilter(page, size, sortBy, sortDirection,
                status, paymentStatus, searchKeyword, fromDate, toDate,
                orderType, eventId, isGuestPurchase, paymentMethod, createdBy, minPrice, maxPrice);
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

    @GetMapping("/{orderId}")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF')")
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
                status, paymentStatus, searchKeyword, fromDate, toDate,
                null, null, null, null, null, null, null);

        PageResponseDTO<OrderResponse> response = orderService.getAllOrders(userId, filter);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy danh sách đơn hàng thành công",
                        response,
                        HttpStatus.OK
                )
        );
    }

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

    @PostMapping("/{orderId}/confirm")
    @PreAuthorize("hasAnyRole('STAFF', 'ADMIN', 'MANAGER')")
    public ResponseEntity<ApiResponseDTO<Void>> confirmOrder(
            @PathVariable String orderId,
            @RequestParam(required = false) String reason) {

        orderService.confirmOrder(orderId, reason);

        return ResponseEntity.ok(
                ApiResponseDTO.success("Xác nhận đơn hàng thành công", null, HttpStatus.OK)
        );
    }


    @PostMapping("/{orderId}/process")
    @PreAuthorize("hasAnyRole('STAFF', 'ADMIN', 'MANAGER')")
    public ResponseEntity<ApiResponseDTO<Void>> processOrder(
            @PathVariable String orderId,
            @RequestParam(required = false) String reason) {

        orderService.processOrder(orderId, reason);

        return ResponseEntity.ok(
                ApiResponseDTO.success("Bắt đầu xử lý đơn hàng thành công", null, HttpStatus.OK)
        );
    }


    @PostMapping("/{orderId}/ship")
    @PreAuthorize("hasAnyRole('STAFF', 'ADMIN', 'MANAGER')")
    public ResponseEntity<ApiResponseDTO<ShipmentInfoResponse>> shipOrder(
            @PathVariable String orderId,
            @Valid @RequestBody CreateShipmentRequestDTO request) {

        ShipmentInfoResponse response = orderService.shipOrder(orderId, request);

        return ResponseEntity.ok(
                ApiResponseDTO.success("Tạo vận đơn thành công", response, HttpStatus.OK)
        );
    }

    @PostMapping("/my-orders/{orderId}/complete")
    @PreAuthorize("hasRole('CUSTOMER')")
    public ResponseEntity<ApiResponseDTO<String>> completeMyOrder(
            @PathVariable String orderId,
            Authentication authentication) {
        Long userId = extractUserId(authentication);
        orderService.completeOrderByCustomer(orderId, userId);
        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Hoàn thành đơn hàng thành công",
                        null,
                        HttpStatus.OK
                )
        );
    }


    @PostMapping("/{orderId}/complete")
    @PreAuthorize("hasAnyRole('STAFF', 'ADMIN', 'MANAGER')")
    public ResponseEntity<ApiResponseDTO<Void>> completeOrder(
            @PathVariable String orderId,
            @RequestParam(required = false) String reason) {

        orderService.completeOrder(orderId, reason);

        return ResponseEntity.ok(
                ApiResponseDTO.success("Hoàn thành đơn hàng thành công", null, HttpStatus.OK)
        );
    }
    @PostMapping("/{orderId}/cancel")
    @PreAuthorize("hasAnyRole('STAFF', 'ADMIN', 'MANAGER', 'CUSTOMER')")
    public ResponseEntity<ApiResponseDTO<Void>> cancelOrder(
            @PathVariable String orderId,
            @RequestParam(required = false) String reason,
            Authentication authentication
            ) {
        Long userId = extractUserId(authentication);
        String userRole = extractRole(authentication);
        orderService.cancelOrder(orderId, reason, userId, userRole);
        return ResponseEntity.ok(
                ApiResponseDTO.success("Hủy đơn hàng thành công", null, HttpStatus.OK)
        );
    }


    private OrderFilterRequest buildFilter(Integer page, Integer size, String sortBy,
                                           String sortDirection, String status,
                                           String paymentStatus, String searchKeyword,
                                           String fromDate, String toDate,
                                           String orderType, Long eventId, Boolean isGuestPurchase,
                                           String paymentMethod, String createdBy,
                                           BigDecimal minPrice, BigDecimal maxPrice) {
        OrderFilterRequest filter = OrderFilterRequest.builder()
                .page(page)
                .size(size)
                .sortBy(sortBy)
                .sortDirection(sortDirection)
                .searchKeyword(searchKeyword)
                .fromDate(fromDate)
                .toDate(toDate)
                .eventId(eventId)
                .isGuestPurchase(isGuestPurchase)
                .createdBy(createdBy)
                .minPrice(minPrice)
                .maxPrice(maxPrice)
                .build();

        try {
            if (status != null && !status.trim().isEmpty()) {
                filter.setStatus(OrderStatus.valueOf(status.toUpperCase()));
            }
            if (paymentStatus != null && !paymentStatus.trim().isEmpty()) {
                filter.setPaymentStatus(PaymentStatus.valueOf(paymentStatus.toUpperCase()));
            }
            if (orderType != null && !orderType.trim().isEmpty()) {
                filter.setOrderType(OrderType.valueOf(orderType.toUpperCase()));
            }
            if (paymentMethod != null && !paymentMethod.trim().isEmpty()) {
                filter.setPaymentMethod(PaymentMethod.valueOf(paymentMethod.toUpperCase()));
            }
        } catch (IllegalArgumentException e) {
            log.warn("Invalid enum value: {}", e.getMessage());
        }

        return filter;
    }

    private Long extractUserId(Authentication authentication) {
        return Long.parseLong(authentication.getName());
    }

    private String extractRole(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .findFirst()
                .orElse("ROLE_CUSTOMER");
    }
}
