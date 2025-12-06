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
    @Operation(
            summary = "Create offline order",
            description = "Tạo đơn hàng offline tại sự kiện. CASH không cần ảnh, BANK_TRANSFER bắt buộc có ảnh bill."
    )
    @PreAuthorize("hasAnyRole('STAFF', 'MANAGER', 'ADMIN')")
    public ResponseEntity<ApiResponseDTO<OrderOfflineResponse>> createOrderOffline(
            @Valid @RequestPart("order") CreateOrderOfflineRequest request,
            @RequestPart(value = "paymentProofImage", required = false) MultipartFile paymentProofImage,
            HttpServletRequest httpRequest) {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        log.info("Staff {} creating offline order. Event: {}, Customer: {}, PaymentMethod: {}, HasImage: {}",
                auth.getName(),
                request.getEventId(),
                request.getCustomerId(),
                request.getPaymentMethod(),
                paymentProofImage != null);

        // Validate payment method
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

        // Validate BANK_TRANSFER bắt buộc có ảnh
        if ("BANK_TRANSFER".equals(request.getPaymentMethod())) {
            if (paymentProofImage == null || paymentProofImage.isEmpty()) {
                return ResponseEntity.badRequest().body(
                        ApiResponseDTO.error(
                                "Thanh toán chuyển khoản yêu cầu ảnh bill xác nhận",
                                HttpStatus.BAD_REQUEST,
                                httpRequest.getRequestURI()
                        )
                );
            }

            // Validate file type
            String contentType = paymentProofImage.getContentType();
            if (contentType == null || !contentType.startsWith("image/")) {
                return ResponseEntity.badRequest().body(
                        ApiResponseDTO.error(
                                "File phải là ảnh (jpg, png, jpeg)",
                                HttpStatus.BAD_REQUEST,
                                httpRequest.getRequestURI()
                        )
                );
            }

            // Validate file size (max 5MB)
            if (paymentProofImage.getSize() > 5 * 1024 * 1024) {
                return ResponseEntity.badRequest().body(
                        ApiResponseDTO.error(
                                "Kích thước ảnh không được vượt quá 5MB",
                                HttpStatus.BAD_REQUEST,
                                httpRequest.getRequestURI()
                        )
                );
            }
        }

        OrderOfflineResponse response = orderOfflineService.createOrderOffline(
                request,
                paymentProofImage
        );

        return ResponseEntity.status(HttpStatus.CREATED).body(
                ApiResponseDTO.success(
                        "Tạo đơn hàng offline thành công",
                        response,
                        HttpStatus.CREATED
                )
        );
    }
}
