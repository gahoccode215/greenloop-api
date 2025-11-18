package com.greenloop.reward.controller;

import com.greenloop.reward.dto.request.CreateVoucherCampaignRequest;
import com.greenloop.reward.dto.request.CreateVoucherRequest;
import com.greenloop.reward.dto.response.ApiResponseDTO;
import com.greenloop.reward.dto.response.VoucherCampaignResponse;
import com.greenloop.reward.enums.VoucherStatus;
import com.greenloop.reward.enums.VoucherType;
import com.greenloop.reward.service.VoucherService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/v1/vouchers")
@RequiredArgsConstructor
@Slf4j
public class VoucherController {
    private final VoucherService voucherService;

    @PostMapping("/campaigns")
    @Operation(summary = "Create vouchers for active voucher campaigns", description = "This endpoint creates vouchers for all active voucher campaigns.")
    @Tag(name = "Voucher Campaign Management", description = "APIs for managing vouchers and voucher campaigns")
    public ResponseEntity<ApiResponseDTO<Long>> createVoucherCampaigns(@RequestBody @Valid CreateVoucherCampaignRequest request) {
        log.info("Create vouchers for active voucher campaigns");
        Long campaignId = voucherService.createVoucherCampaign(request);
        return ResponseEntity.ok(
                ApiResponseDTO.<Long>builder()
                        .data(campaignId)
                        .message("Vouchers created successfully for campaign ID: " + campaignId)
                        .build()
        );
    }

    @PutMapping("/campaigns/{campaignId}")
    @Operation(summary = "Update an existing voucher campaign", description = "This endpoint updates the details of an existing voucher campaign.")
    @Tag(name = "Voucher Campaign Management", description = "APIs for managing vouchers and voucher campaigns")
    public ResponseEntity<ApiResponseDTO<Void>> updateVoucherCampaign(
            @PathVariable Long campaignId,
            @RequestBody @Valid CreateVoucherCampaignRequest request) {
        log.info("Update voucher campaign with ID: {}", campaignId);
        voucherService.updateVoucherCampaign(request, campaignId);
        return ResponseEntity.ok(
                ApiResponseDTO.<Void>builder()
                        .message("Voucher campaign updated successfully with ID: " + campaignId)
                        .build()
        );
    }


    @PostMapping
    @Operation(summary = "Create a new voucher", description = "This endpoint creates a new voucher based on the provided details.")
    @Tag(name = "Voucher Management", description = "APIs for managing vouchers and voucher campaigns")
    public ResponseEntity<ApiResponseDTO<Long>> createVoucher(@RequestBody @Valid CreateVoucherRequest request) {
        log.info("Create a new voucher");
        Long voucherId = voucherService.createVoucher(request);
        return ResponseEntity.ok(
                ApiResponseDTO.<Long>builder()
                        .data(voucherId)
                        .message("Voucher created successfully with ID: " + voucherId)
                        .build()
        );
    }

    @PutMapping("/{voucherId}")
    @Operation(summary = "Update an existing voucher", description = "This endpoint updates the details of an existing voucher.")
    @Tag(name = "Voucher Management", description = "APIs for managing vouchers and voucher campaigns")
    public ResponseEntity<ApiResponseDTO<Void>> updateVoucher(
            @PathVariable Long voucherId,
            @RequestBody @Valid CreateVoucherRequest request) {
        log.info("Update voucher with ID: {}", voucherId);
        voucherService.updateVoucher(request, voucherId);
        return ResponseEntity.ok(
                ApiResponseDTO.<Void>builder()
                        .message("Voucher updated successfully with ID: " + voucherId)
                        .build()
        );
    }

    @PatchMapping("/{voucherId}/toggle-status")
    @Operation(summary = "Toggle voucher active status", description = "This endpoint toggles the active status of a voucher.")
    @Tag(name = "Voucher Management", description = "APIs for managing vouchers and voucher campaigns")
    public ResponseEntity<ApiResponseDTO<Void>> toggleVoucherStatus(@PathVariable Long voucherId) {
        log.info("Toggle active status for voucher with ID: {}", voucherId);
        voucherService.toggleVoucherStatus(voucherId);
        return ResponseEntity.ok(
                ApiResponseDTO.<Void>builder()
                        .message("Voucher status toggled successfully for ID: " + voucherId)
                        .build()
        );
    }

    @PatchMapping("/{voucherId}/change-status")
    @Operation(summary = "Change voucher status", description = "This endpoint changes the status of a voucher.")
    @Tag(name = "Voucher Management", description = "APIs for managing vouchers and voucher campaigns")
    public ResponseEntity<ApiResponseDTO<Void>> changeVoucherStatus(
            @PathVariable Long voucherId,
            @RequestParam VoucherStatus status) {
        log.info("Change status for voucher with ID: {} to {}", voucherId, status);
        voucherService.changeVoucherStatus(voucherId, status);
        return ResponseEntity.ok(
                ApiResponseDTO.<Void>builder()
                        .message("Voucher status changed successfully for ID: " + voucherId)
                        .build()
        );
    }

    @GetMapping("/campaigns/customer")
    @Operation(summary = "Get voucher campaigns for customers", description = "This endpoint retrieves voucher campaigns available to customers with optional filters.")
    @Tag(name = "Voucher Campaign Management", description = "APIs for managing vouchers and voucher campaigns")
    public ResponseEntity<ApiResponseDTO<Page<VoucherCampaignResponse>>> getVoucherCampaignsForCustomer(
            @RequestParam(required = false) String name,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        log.info("Get voucher campaigns for customers with filters - name: {}, from: {}, to: {}", name, from, to);
        Page<VoucherCampaignResponse> campaigns = voucherService.getVoucherCampaignsForCustomer(name, from, to, page, size);
        return ResponseEntity.ok(
                ApiResponseDTO.<Page<VoucherCampaignResponse>>builder()
                        .data(campaigns)
                        .message("Voucher campaigns retrieved successfully for customers")
                        .build()
        );
    }

    @GetMapping("/campaigns/admin")
    @Operation(summary = "Get voucher campaigns for admins", description = "This endpoint retrieves voucher campaigns available to admins with optional filters.")
    @Tag(name = "Voucher Campaign Management", description = "APIs for managing vouchers and voucher campaigns")
    public ResponseEntity<ApiResponseDTO<Page<VoucherCampaignResponse>>> getVoucherCampaignsForAdmin(
            @RequestParam(required = false) String name,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        log.info("Get voucher campaigns for admins with filters - name: {}, from: {}, to: {}", name, from, to);
        Page<VoucherCampaignResponse> campaigns = voucherService.getVoucherCampaignsForAdmin(name, from, to, page, size);
        return ResponseEntity.ok(
                ApiResponseDTO.<Page<VoucherCampaignResponse>>builder()
                        .data(campaigns)
                        .message("Voucher campaigns retrieved successfully for admins")
                        .build()
        );
    }

    @GetMapping("/customer")
    @Operation(summary = "Get vouchers for customers", description = "This endpoint retrieves vouchers available to customers with optional filters.")
    @Tag(name = "Voucher Management", description = "APIs for managing vouchers and voucher campaigns")
    public ResponseEntity<ApiResponseDTO<Page<?>>> getVouchersForCustomer(
            @RequestParam(required = false) Long campaignId,
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String name,
            @RequestParam(required = false) VoucherType voucherType,
            @RequestParam(required = false) VoucherStatus status,
            @RequestParam(required = false) BigDecimal minOrderValue,
            @RequestParam(required = false) BigDecimal maxDiscount,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        log.info("Get vouchers for customers with filters - campaignId: {}, code: {}, name: {}", campaignId, code, name);
        Page<?> vouchers = voucherService.getVouchersForCustomer(campaignId, code, name, voucherType, status, minOrderValue, maxDiscount, page, size);
        return ResponseEntity.ok(
                ApiResponseDTO.<Page<?>>builder()
                        .data(vouchers)
                        .message("Vouchers retrieved successfully for customers")
                        .build()
        );
    }


//    @GetMapping("/admin")
//    @Operation(summary = "Get vouchers for admins", description = "This endpoint retrieves vouchers available to admins with optional filters.")
//    @Tag(name = "Voucher Management", description = "APIs for managing vouchers and voucher campaigns")
//    public ResponseEntity<ApiResponseDTO<Page<?>>> getVouchersForAdmin(
//            @RequestParam(required = false) Long campaignId,
//            @RequestParam(required = false) String code,
//            @RequestParam(required = false) String name,
//            @RequestParam(required = false) VoucherType voucherType,
//            @RequestParam(required = false) VoucherStatus status,
//            @RequestParam(required = false) BigDecimal minOrderValue,
//            @RequestParam(required = false) BigDecimal maxDiscount,

}
