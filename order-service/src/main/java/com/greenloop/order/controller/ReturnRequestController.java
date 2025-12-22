package com.greenloop.order.controller;

import com.greenloop.order.dto.request.CreateReturnRequestRequest;
import com.greenloop.order.dto.request.ReturnRequestFilterRequest;
import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.response.PageResponseDTO;
import com.greenloop.order.dto.response.ReturnRequestResponse;
import com.greenloop.order.enums.ReturnReason;
import com.greenloop.order.enums.ReturnRequestStatus;
import com.greenloop.order.enums.ReturnType;
import com.greenloop.order.service.ReturnRequestService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.math.BigDecimal;
import java.util.List;

@RestController
@RequestMapping("/api/v1/return-requests")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Return Request Management", description = "API quản lý yêu cầu trả hàng")
public class ReturnRequestController {

    private final ReturnRequestService returnRequestService;

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF')")
    @Operation(summary = "Lấy danh sách tất cả yêu cầu trả hàng với filter",
            description = "Staff/Admin lấy danh sách tất cả yêu cầu trả hàng với filter đa điều kiện")
    public ResponseEntity<ApiResponseDTO<PageResponseDTO<ReturnRequestResponse>>> getAllReturnRequests(
            @RequestParam(defaultValue = "0") Integer page,
            @RequestParam(defaultValue = "10") Integer size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "DESC") String sortDirection,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String returnReason,
            @RequestParam(required = false) String returnType,
            @RequestParam(required = false) Long customerId,
            @RequestParam(required = false) String orderId,
            @RequestParam(required = false) String searchKeyword,
            @RequestParam(required = false) String fromDate,
            @RequestParam(required = false) String toDate,
            @RequestParam(required = false) BigDecimal minAmount,
            @RequestParam(required = false) BigDecimal maxAmount) {

        ReturnRequestFilterRequest filter = buildFilter(
                page, size, sortBy, sortDirection,
                status, returnReason, returnType, customerId, orderId,
                searchKeyword, fromDate, toDate, minAmount, maxAmount
        );

        PageResponseDTO<ReturnRequestResponse> response = returnRequestService.getAllReturnRequests(filter);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy danh sách yêu cầu trả hàng thành công",
                        response,
                        HttpStatus.OK
                )
        );
    }

    @PostMapping(value = "/orders/{orderId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("hasRole('CUSTOMER')")
    @Operation(summary = "Tạo yêu cầu trả hàng với ảnh minh chứng",
            description = "Customer tạo yêu cầu trả một hoặc nhiều sản phẩm trong đơn đã hoàn thành (trong vòng 7 ngày)")
    public ResponseEntity<ApiResponseDTO<ReturnRequestResponse>> createReturnRequest(
            Authentication authentication,
            @PathVariable String orderId,
            @RequestPart("request") @Valid CreateReturnRequestRequest request,
            @RequestPart(value = "images", required = false) List<MultipartFile> images) {

        Long customerId = Long.parseLong(authentication.getName());

        ReturnRequestResponse response = returnRequestService.createReturnRequest(
                customerId, orderId, request, images);

        return ResponseEntity.status(HttpStatus.CREATED).body(
                ApiResponseDTO.success(
                        "Yêu cầu trả hàng đã được tạo thành công. Vui lòng chờ nhân viên duyệt.",
                        response,
                        HttpStatus.CREATED
                )
        );
    }

    @GetMapping("/{returnRequestId}")
    @PreAuthorize("hasAnyRole('CUSTOMER', 'STAFF', 'ADMIN', 'MANAGER')")
    @Operation(summary = "Xem chi tiết yêu cầu trả hàng")
    public ResponseEntity<ApiResponseDTO<ReturnRequestResponse>> getReturnRequestById(
            @PathVariable Long returnRequestId) {

        ReturnRequestResponse response = returnRequestService.getReturnRequestById(returnRequestId);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy thông tin yêu cầu trả hàng thành công",
                        response,
                        HttpStatus.OK
                )
        );
    }

    @GetMapping("/orders/{orderId}")
    @PreAuthorize("hasAnyRole('CUSTOMER', 'STAFF', 'ADMIN', 'MANAGER')")
    @Operation(summary = "Lấy danh sách yêu cầu trả hàng theo đơn hàng")
    public ResponseEntity<ApiResponseDTO<PageResponseDTO<ReturnRequestResponse>>> getReturnRequestsByOrder(
            @PathVariable String orderId,
            @RequestParam(defaultValue = "0") Integer page,
            @RequestParam(defaultValue = "10") Integer size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "DESC") String sortDirection) {

        PageResponseDTO<ReturnRequestResponse> response = returnRequestService
                .getReturnRequestsByOrder(orderId, page, size, sortBy, sortDirection);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy danh sách yêu cầu trả hàng thành công",
                        response,
                        HttpStatus.OK
                )
        );
    }

    @GetMapping("/my-returns")
    @PreAuthorize("hasRole('CUSTOMER')")
    @Operation(summary = "Xem danh sách yêu cầu trả hàng của tôi")
    public ResponseEntity<ApiResponseDTO<PageResponseDTO<ReturnRequestResponse>>> getMyReturnRequests(
            Authentication authentication,
            @RequestParam(defaultValue = "0") Integer page,
            @RequestParam(defaultValue = "10") Integer size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "DESC") String sortDirection) {

        Long customerId = Long.parseLong(authentication.getName());

        PageResponseDTO<ReturnRequestResponse> response = returnRequestService
                .getReturnRequestsByCustomer(customerId, page, size, sortBy, sortDirection);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy danh sách yêu cầu trả hàng thành công",
                        response,
                        HttpStatus.OK
                )
        );
    }

    private ReturnRequestFilterRequest buildFilter(
            Integer page, Integer size, String sortBy, String sortDirection,
            String status, String returnReason, String returnType,
            Long customerId, String orderId, String searchKeyword,
            String fromDate, String toDate, BigDecimal minAmount, BigDecimal maxAmount) {

        ReturnRequestFilterRequest filter = ReturnRequestFilterRequest.builder()
                .page(page)
                .size(size)
                .sortBy(sortBy)
                .sortDirection(sortDirection)
                .customerId(customerId)
                .orderId(orderId)
                .searchKeyword(searchKeyword)
                .fromDate(fromDate)
                .toDate(toDate)
                .minAmount(minAmount)
                .maxAmount(maxAmount)
                .build();

        try {
            if (status != null && !status.trim().isEmpty()) {
                filter.setStatus(ReturnRequestStatus.valueOf(status.toUpperCase()));
            }
            if (returnReason != null && !returnReason.trim().isEmpty()) {
                filter.setReturnReason(ReturnReason.valueOf(returnReason.toUpperCase()));
            }
            if (returnType != null && !returnType.trim().isEmpty()) {
                filter.setReturnType(ReturnType.valueOf(returnType.toUpperCase()));
            }
        } catch (IllegalArgumentException e) {
            log.warn("Invalid enum value: {}", e.getMessage());
        }

        return filter;
    }
}
