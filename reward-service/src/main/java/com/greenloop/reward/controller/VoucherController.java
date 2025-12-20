package com.greenloop.reward.controller;

import com.greenloop.reward.dto.request.CreateVoucherCampaignRequest;
import com.greenloop.reward.dto.request.CreateVoucherRequest;
import com.greenloop.reward.dto.response.*;
import com.greenloop.reward.enums.VoucherStatus;
import com.greenloop.reward.enums.VoucherType;
import com.greenloop.reward.service.VoucherService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.springframework.data.domain.Page;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/vouchers")
@RequiredArgsConstructor
@Slf4j
public class VoucherController {
  private final VoucherService voucherService;

  @PostMapping("/campaigns")
  @Operation(
      summary = "Create vouchers for active voucher campaigns",
      description = "This endpoint creates vouchers for all active voucher campaigns.")
  @Tag(
      name = "Voucher Campaign Management",
      description = "APIs for managing vouchers and voucher campaigns")
  @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
  public ResponseEntity<ApiResponseDTO<Long>> createVoucherCampaigns(
      @RequestBody @Valid CreateVoucherCampaignRequest request) {
    log.info("Create vouchers for active voucher campaigns");
    Long campaignId = voucherService.createVoucherCampaign(request);
    return ResponseEntity.ok(
        ApiResponseDTO.<Long>builder()
            .data(campaignId)
            .success(true)
            .statusCode(HttpStatus.OK.value())
            .message("Tạo voucher thành công cho campaign ID: " + campaignId)
            .build());
  }

  @PutMapping("/campaigns/{campaignId}")
  @Operation(
      summary = "Update an existing voucher campaign",
      description = "This endpoint updates the details of an existing voucher campaign.")
  @Tag(
      name = "Voucher Campaign Management",
      description = "APIs for managing vouchers and voucher campaigns")
  @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
  public ResponseEntity<ApiResponseDTO<Void>> updateVoucherCampaign(
      @PathVariable Long campaignId, @RequestBody @Valid CreateVoucherCampaignRequest request) {
    log.info("Update voucher campaign with ID: {}", campaignId);
    voucherService.updateVoucherCampaign(request, campaignId);
    return ResponseEntity.ok(
        ApiResponseDTO.<Void>builder()
            .success(true)
            .statusCode(HttpStatus.OK.value())
            .message("Cập nhật campaign voucher thành công với ID: " + campaignId)
            .build());
  }

  @PostMapping
  @Operation(
      summary = "Create a new voucher",
      description = "This endpoint creates a new voucher based on the provided details.")
  @Tag(
      name = "Voucher Management",
      description = "APIs for managing vouchers and voucher campaigns")
  @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
  public ResponseEntity<ApiResponseDTO<Long>> createVoucher(
      @RequestBody @Valid CreateVoucherRequest request) {
    log.info("Create a new voucher");
    Long voucherId = voucherService.createVoucher(request);
    return ResponseEntity.ok(
        ApiResponseDTO.<Long>builder()
            .data(voucherId)
            .success(true)
            .statusCode(HttpStatus.OK.value())
            .message("Tạo voucher thành công với ID: " + voucherId)
            .build());
  }

  @PutMapping("/{voucherId}")
  @Operation(
      summary = "Update an existing voucher",
      description = "This endpoint updates the details of an existing voucher.")
  @Tag(
      name = "Voucher Management",
      description = "APIs for managing vouchers and voucher campaigns")
  @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
  public ResponseEntity<ApiResponseDTO<Void>> updateVoucher(
      @PathVariable Long voucherId, @RequestBody @Valid CreateVoucherRequest request) {
    log.info("Update voucher with ID: {}", voucherId);
    voucherService.updateVoucher(request, voucherId);
    return ResponseEntity.ok(
        ApiResponseDTO.<Void>builder()
            .success(true)
            .statusCode(HttpStatus.OK.value())
            .message("Cập nhật voucher thành công với ID: " + voucherId)
            .build());
  }

  @PatchMapping("/{voucherId}/toggle-status")
  @Operation(
      summary = "Toggle voucher active status",
      description = "This endpoint toggles the active status of a voucher.")
  @Tag(
      name = "Voucher Management",
      description = "APIs for managing vouchers and voucher campaigns")
  @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
  public ResponseEntity<ApiResponseDTO<Void>> toggleVoucherStatus(@PathVariable Long voucherId) {
    log.info("Toggle active status for voucher with ID: {}", voucherId);
    voucherService.toggleVoucherStatus(voucherId);
    return ResponseEntity.ok(
        ApiResponseDTO.<Void>builder()
            .success(true)
            .statusCode(HttpStatus.OK.value())
            .message("Chuyển đổi trạng thái kích hoạt voucher thành công với ID: " + voucherId)
            .build());
  }

  @PatchMapping("/{voucherId}/change-status")
  @Operation(
      summary = "Change voucher status",
      description = "This endpoint changes the status of a voucher.")
  @Tag(
      name = "Voucher Management",
      description = "APIs for managing vouchers and voucher campaigns")
  @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
  public ResponseEntity<ApiResponseDTO<Void>> changeVoucherStatus(
      @PathVariable Long voucherId, @RequestParam VoucherStatus status) {
    log.info("Change status for voucher with ID: {} to {}", voucherId, status);
    voucherService.changeVoucherStatus(voucherId, status);
    return ResponseEntity.ok(
        ApiResponseDTO.<Void>builder()
            .success(true)
            .statusCode(HttpStatus.OK.value())
            .message("Thay đổi trạng thái voucher thành công với ID: " + voucherId)
            .build());
  }

  @GetMapping("/campaigns/customer")
  @Operation(
      summary = "Get voucher campaigns for customers",
      description =
          "This endpoint retrieves voucher campaigns available to customers with optional filters.")
  @Tag(
      name = "Voucher Campaign Management",
      description = "APIs for managing vouchers and voucher campaigns")
  public ResponseEntity<ApiResponseDTO<Page<VoucherCampaignResponse>>>
      getVoucherCampaignsForCustomer(
          @RequestParam(required = false) String name,
          @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
              LocalDateTime from,
          @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
              LocalDateTime to,
          @RequestParam(defaultValue = "0") int page,
          @RequestParam(defaultValue = "10") int size) {
    log.info(
        "Get voucher campaigns for customers with filters - name: {}, from: {}, to: {}",
        name,
        from,
        to);
    Page<VoucherCampaignResponse> campaigns =
        voucherService.getVoucherCampaignsForCustomer(name, from, to, page, size);
    return ResponseEntity.ok(
        ApiResponseDTO.<Page<VoucherCampaignResponse>>builder()
            .data(campaigns)
            .success(true)
            .statusCode(HttpStatus.OK.value())
            .message("Lấy danh sách chiến dịch voucher cho khách hàng thành công")
            .build());
  }

  @GetMapping("/campaigns/admin")
  @Operation(
      summary = "Get voucher campaigns for admins",
      description =
          "This endpoint retrieves voucher campaigns available to admins with optional filters.")
  @Tag(
      name = "Voucher Campaign Management",
      description = "APIs for managing vouchers and voucher campaigns")
  @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER') or hasRole('ROLE_STAFF')")
  public ResponseEntity<ApiResponseDTO<Page<VoucherCampaignResponse>>> getVoucherCampaignsForAdmin(
      @RequestParam(required = false) String name,
      @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
          LocalDateTime from,
      @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME)
          LocalDateTime to,
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "10") int size) {
    log.info(
        "Get voucher campaigns for admins with filters - name: {}, from: {}, to: {}",
        name,
        from,
        to);
    Page<VoucherCampaignResponse> campaigns =
        voucherService.getVoucherCampaignsForAdmin(name, from, to, page, size);
    return ResponseEntity.ok(
        ApiResponseDTO.<Page<VoucherCampaignResponse>>builder()
            .data(campaigns)
            .success(true)
            .statusCode(HttpStatus.OK.value())
            .message("Lấy danh sách chiến dịch voucher cho admin thành công")
            .build());
  }

  @GetMapping("/customer")
  @Operation(
      summary = "Get vouchers for customers",
      description =
          "This endpoint retrieves vouchers available to customers with optional filters.")
  @Tag(
      name = "Voucher Management",
      description = "APIs for managing vouchers and voucher campaigns")
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
    log.info(
        "Get vouchers for customers with filters - campaignId: {}, code: {}, name: {}",
        campaignId,
        code,
        name);
    Page<?> vouchers =
        voucherService.getVouchersForCustomer(
            campaignId, code, name, voucherType, status, minOrderValue, maxDiscount, page, size);
    return ResponseEntity.ok(
        ApiResponseDTO.<Page<?>>builder()
            .data(vouchers)
            .success(true)
            .statusCode(HttpStatus.OK.value())
            .message("Lấy danh sách voucher cho khách hàng thành công")
            .build());
  }

  @GetMapping("/admin")
  @Operation(
      summary = "Get vouchers for admins",
      description = "This endpoint retrieves vouchers available to admins with optional filters.")
  @Tag(
      name = "Voucher Management",
      description = "APIs for managing vouchers and voucher campaigns")
  @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER') or hasRole('ROLE_STAFF')")
  public ResponseEntity<ApiResponseDTO<Page<?>>> getVouchersForAdmin(
      @RequestParam(required = false) Long campaignId,
      @RequestParam(required = false) String code,
      @RequestParam(required = false) String name,
      @RequestParam(required = false) VoucherType voucherType,
      @RequestParam(required = false) VoucherStatus status,
      @RequestParam(required = false) BigDecimal minOrderValue,
      @RequestParam(required = false) BigDecimal maxDiscount,
      @RequestParam(required = false) Boolean active,
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "10") int size) {
    log.info(
        "Get vouchers for admins with filters - campaignId: {}, code: {}, name: {}",
        campaignId,
        code,
        name);
    Page<?> vouchers =
        voucherService.getVouchersForAdmin(
            campaignId,
            code,
            name,
            voucherType,
            status,
            minOrderValue,
            maxDiscount,
            active,
            page,
            size);
    return ResponseEntity.ok(
        ApiResponseDTO.<Page<?>>builder()
            .data(vouchers)
            .success(true)
            .statusCode(HttpStatus.OK.value())
            .message("Lấy danh sách voucher cho admin thành công")
            .build());
  }

  @PostMapping("/{voucherId}/redeem")
  @Operation(
      summary = "Redeem a voucher",
      description = "This endpoint redeems a voucher for the authenticated user.")
  @Tag(
      name = "Voucher Management",
      description = "APIs for managing vouchers and voucher campaigns")
  @PreAuthorize("isAuthenticated()")
  public ResponseEntity<ApiResponseDTO<Long>> redeemVoucher(@PathVariable Long voucherId) {
    log.info("Redeem voucher with ID: {}", voucherId);
    Long redemptionId = voucherService.redeemVoucher(voucherId);
    return ResponseEntity.ok(
        ApiResponseDTO.<Long>builder()
            .data(redemptionId)
            .success(true)
            .statusCode(HttpStatus.OK.value())
            .message("Đổi voucher thành công, mã giao dịch: " + redemptionId)
            .build());
  }

  @GetMapping("/my-vouchers")
  @Operation(
      summary = "Get my vouchers",
      description = "This endpoint retrieves the vouchers assigned to the authenticated user.")
  @Tag(
      name = "Voucher Management",
      description = "APIs for managing vouchers and voucher campaigns")
  @PreAuthorize("isAuthenticated()")
  public ResponseEntity<ApiResponseDTO<?>> myVouchers() {
    log.info("Get my vouchers");
    var vouchers = voucherService.myVouchers();
    return ResponseEntity.ok(
        ApiResponseDTO.<Object>builder()
            .data(vouchers)
            .success(true)
            .statusCode(HttpStatus.OK.value())
            .message("Lấy danh sách voucher của bạn thành công")
            .build());
  }

  @PostMapping("/internal/users/validate-voucher/{voucherUserId}")
  @Operation(
      summary = "Validate voucher for a user (Internal)",
      description = "This internal endpoint validates a voucher for a specific user.")
  @Tag(
      name = "Voucher Management",
      description = "APIs for managing vouchers and voucher campaigns")
  public ResponseEntity<ApiResponseDTO<UserVoucherResponse>> validateVoucherForUser(
      @PathVariable("voucherUserId") Long voucherUserId) {
    log.info("Validate voucher with ID: {} for user", voucherUserId);
    UserVoucherResponse voucherResponse = voucherService.validateVoucherUsage(voucherUserId);
    return ResponseEntity.ok(
        ApiResponseDTO.<UserVoucherResponse>builder()
            .data(voucherResponse)
            .success(true)
            .statusCode(HttpStatus.OK.value())
            .message("Xác thực voucher thành công cho user ID: " + voucherUserId)
            .build());
  }



    @GetMapping("/export")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_MANAGER')")
    @Operation(summary = "Export Vouchers", description = "Export vouchers to CSV")
    public void exportVouchers(
            @RequestParam(required = false) Long campaignId,
            @RequestParam(required = false) VoucherStatus status,
            @RequestParam(required = false) VoucherType type,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime expiryDateFrom,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime expiryDateTo,
            @RequestParam(required = false) Integer minPointToRedeem,
            @RequestParam(required = false) Integer maxPointToRedeem,
            @RequestParam(defaultValue = "false") boolean includeExpired,
            HttpServletResponse response) throws IOException {

        try {
            List<VoucherExportDTO> exportData = voucherService.getExportDataVoucher(
                    campaignId, status, type, expiryDateFrom, expiryDateTo,
                    minPointToRedeem, maxPointToRedeem, includeExpired);

            response.setContentType("text/csv; charset=UTF-8");
            response.setHeader("Content-Disposition", "attachment; filename=vouchers_export_"
                    + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss")) + ".csv");

            try (PrintWriter writer = response.getWriter();
                 CSVPrinter csvPrinter = new CSVPrinter(writer,
                         CSVFormat.DEFAULT.withHeader(
                                 "CampaignId", "CampaignName", "CampaignDescription",
                                 "CampaignStartDate", "CampaignEndDate",
                                 "VoucherId", "VoucherCode", "VoucherName", "VoucherDescription",
                                 "Type", "Value", "MinOrderValue", "MaxDiscount",
                                 "Status", "ExpiryDate", "Quantity", "UsedQuantity", "AvailableQuantity",
                                 "PointToRedeem", "CreatedAt", "UpdatedAt"))) {

                for (VoucherExportDTO dto : exportData) {
                    csvPrinter.printRecord(
                            dto.getCampaignId(), dto.getCampaignName(), dto.getCampaignDescription(),
                            dto.getCampaignStartDate(), dto.getCampaignEndDate(),
                            dto.getVoucherId(), dto.getVoucherCode(), dto.getVoucherName(), dto.getVoucherDescription(),
                            dto.getType(), dto.getValue(), dto.getMinOrderValue(), dto.getMaxDiscount(),
                            dto.getStatus(), dto.getExpiryDate(), dto.getQuantity(), dto.getUsedQuantity(),
                            dto.getAvailableQuantity(), dto.getPointToRedeem(), dto.getCreatedAt(), dto.getUpdatedAt()
                    );
                }
            }
        } catch (Exception e) {
            log.error("Error exporting vouchers", e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Failed to export vouchers\"}");
        }
    }


    @GetMapping("/campaign/export")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_MANAGER')")
    @Operation(summary = "Export Voucher Campaigns", description = "Export voucher campaigns to CSV")
    public void exportCampaigns(
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime startDateFrom,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime startDateTo,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime endDateFrom,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime endDateTo,
            @RequestParam(defaultValue = "false") boolean includeExpired,
            @RequestParam(defaultValue = "false") boolean includeVoucherDetails,
            HttpServletResponse response) throws IOException {

        try {
            List<VoucherCampaignExportDTO> exportData = voucherService.getExportDataCampaign(
                    startDateFrom, startDateTo, endDateFrom, endDateTo,
                    includeExpired, includeVoucherDetails);

            response.setContentType("text/csv; charset=UTF-8");
            response.setHeader("Content-Disposition", "attachment; filename=voucher_campaigns_export_"
                    + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss")) + ".csv");

            try (PrintWriter writer = response.getWriter();
                 CSVPrinter csvPrinter = new CSVPrinter(writer,
                         CSVFormat.DEFAULT.withHeader(
                                 "CampaignId", "CampaignName", "CampaignDescription",
                                 "StartDate", "EndDate",
                                 "TotalVouchers", "ActiveVouchers", "ExpiredVouchers",
                                 "TotalQuantity", "UsedQuantity", "AvailableQuantity",
                                 "CreatedAt", "UpdatedAt"))) {

                for (VoucherCampaignExportDTO dto : exportData) {
                    csvPrinter.printRecord(
                            dto.getCampaignId(), dto.getCampaignName(), dto.getCampaignDescription(),
                            dto.getStartDate(), dto.getEndDate(),
                            dto.getTotalVouchers(), dto.getActiveVouchers(), dto.getExpiredVouchers(),
                            dto.getTotalQuantity(), dto.getUsedQuantity(), dto.getAvailableQuantity(),
                            dto.getCreatedAt(), dto.getUpdatedAt()
                    );
                }
            }
        } catch (Exception e) {
            log.error("Error exporting campaigns", e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Failed to export campaigns\"}");
        }
    }
}
