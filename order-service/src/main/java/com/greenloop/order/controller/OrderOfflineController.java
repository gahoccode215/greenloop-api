package com.greenloop.order.controller;

import com.greenloop.order.dto.request.CreateOrderOfflineRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.OrderOfflineResponse;
import com.greenloop.order.service.OrderOfflineService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/v1/orders/offline")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Order Offline", description = "Offline Order APIs for Staff")
public class OrderOfflineController {

    private final OrderOfflineService orderOfflineService;

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("hasAnyRole('STAFF', 'MANAGER', 'ADMIN')")
    public ResponseEntity<ApiResponseDTO<OrderOfflineResponse>> createOrderOffline(
            @Valid @RequestPart("order") CreateOrderOfflineRequest request,
            @RequestPart(value = "paymentProofImage", required = false) MultipartFile paymentProofImage,
            HttpServletRequest httpRequest) {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        log.info("Staff {} creating offline order. Event: {}, Customer: {}, PaymentMethod: {}",
                auth.getName(),
                request.getEventId(),
                request.getCustomerId(),
                request.getPaymentMethod());

        // 1. Validate payment method
        if (!"CASH".equals(request.getPaymentMethod()) &&
                !"BANK_TRANSFER".equals(request.getPaymentMethod())) {
            return ResponseEntity.badRequest().body(
                    ApiResponseDTO.error(
                            "Phương thức thanh toán offline chỉ hỗ trợ CASH hoặc BANK_TRANSFER",
                            HttpStatus.BAD_REQUEST,
                            httpRequest.getRequestURI()
                    )
            );
        }

        // 2. BANK_TRANSFER không cần upload ảnh nữa (dùng PayOS)
        if ("BANK_TRANSFER".equals(request.getPaymentMethod()) && paymentProofImage != null) {
            return ResponseEntity.badRequest().body(
                    ApiResponseDTO.error(
                            "BANK_TRANSFER thanh toán qua PayOS, không cần upload ảnh bill",
                            HttpStatus.BAD_REQUEST,
                            httpRequest.getRequestURI()
                    )
            );
        }

        // 3. CASH không cần platform, BANK_TRANSFER cần platform cho returnUrl
        if ("BANK_TRANSFER".equals(request.getPaymentMethod())) {
            if (request.getPlatform() == null || request.getPlatform().isBlank()) {
                // Default platform nếu không truyền
                request.setPlatform("web");
                log.info("Platform not provided, defaulting to 'web'");
            }
        }

        // 4. Gọi service tạo đơn
        OrderOfflineResponse response = orderOfflineService.createOrderOffline(
                request,
                null  // Không truyền paymentProofImage nữa
        );

        // 5. Trả response với message phù hợp
        String successMessage = buildSuccessMessage(request.getPaymentMethod(), response);

        return ResponseEntity.status(HttpStatus.CREATED).body(
                ApiResponseDTO.success(
                        successMessage,
                        response,
                        HttpStatus.CREATED
                )
        );
    }


    private String buildSuccessMessage(String paymentMethod, OrderOfflineResponse response) {
        if ("CASH".equals(paymentMethod)) {
            return String.format("Đơn hàng offline %s hoàn thành. Thanh toán tiền mặt: %,dđ",
                    response.getOrderCode(),
                    response.getTotalPrice().longValue());
        } else {
            return String.format("Đơn hàng offline %s đã tạo. Vui lòng quét mã QR để thanh toán %,dđ",
                    response.getOrderCode(),
                    response.getTotalPrice().longValue());
        }
    }
}
