package com.greenloop.product.controller;

import com.greenloop.product.dto.request.DonationCreateRequest;
import com.greenloop.product.dto.request.UpdateDonationItemStatusRequest;
import com.greenloop.product.dto.response.*;
import com.greenloop.product.enums.ConditionGrade;
import com.greenloop.product.enums.DonationItemStatus;
import com.greenloop.product.service.DonationService;
import com.greenloop.product.utils.ExcelExportUtil;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.poi.ss.usermodel.*;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.time.LocalDateTime;
import java.util.List;

@RestController
@RequestMapping("/api/v1/donations")
@RequiredArgsConstructor
@Slf4j
public class DonationController {
    private final DonationService donationService;

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Create a new donation", description = "Creates a new donation with optional thumbnail images.")
    public ResponseEntity<ApiResponseDTO<Long>> createDonation(@RequestPart("event") @Valid DonationCreateRequest request,
                                                               @RequestPart(value = "thumbnail", required = false) List<MultipartFile> multipartFile) {
        return ResponseEntity.ok(
                ApiResponseDTO.<Long>builder()
                        .data(donationService.createDonation(request, multipartFile))
                        .message("Tạo Đơn Trao Đổi Thành Công")
                        .statusCode(HttpStatus.OK.value())
                        .success(true)
                        .build());
    }

    @GetMapping("/event/{eventId}")
    @Operation(summary = "Get donations by event ID", description = "Retrieves all donations associated with a specific event ID.")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_STAFF', 'ROLE_STORE_MANAGER', 'ROLE_MANAGER')")
    public ResponseEntity<ApiResponseDTO<List<DonationResponse>>> getDonationsByEventId(@PathVariable Long eventId) {

        List<DonationResponse> donations = donationService.getDonationsByEventId(eventId);

        return ResponseEntity.ok(
                ApiResponseDTO.<List<DonationResponse>>builder()
                        .data(donations)
                        .message("Lấy Danh Sách Đơn Trao Đổi Theo Sự Kiện Thành Công")
                        .statusCode(HttpStatus.OK.value())
                        .success(true)
                        .build());

    }

    @GetMapping("/{donationId}")
    @Operation(summary = "Get donation by ID", description = "Retrieves a specific donation by its ID.")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponseDTO<DonationDetailResponse>> getDonationById(@PathVariable Long donationId) {
        DonationDetailResponse donation = donationService.getDonationById(donationId);
        return ResponseEntity.ok(
                ApiResponseDTO.<DonationDetailResponse>builder()
                        .data(donation)
                        .message("Lấy Thông Tin Đơn Trao Đổi Thành Công")
                        .statusCode(HttpStatus.OK.value())
                        .success(true)
                        .build()
        );
    }

    @GetMapping("/my-donations")
    @Operation(summary = "Get my donations", description = "Retrieves donations made by the authenticated user.")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<ApiResponseDTO<List<DonationResponse>>> getMyDonations() {
        List<DonationResponse> myDonations = donationService.getMyDonations();
        return ResponseEntity.ok(
                ApiResponseDTO.<List<DonationResponse>>builder()
                        .data(myDonations)
                        .message("Lấy Danh Sách Đơn Trao Đổi Của Tôi Thành Công")
                        .statusCode(HttpStatus.OK.value())
                        .success(true)
                        .build());
    }

    @PostMapping("/update-status-items")
    @Operation(summary = "Update donation item status",
            description = "Updates the status of donation items based on provided codes.")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_STAFF', 'ROLE_STORE_MANAGER', 'ROLE_MANAGER')")
    public ResponseEntity<ApiResponseDTO<UpdateDonationItemStatusResponse>> updateStatusOfDonationItem(
            @Valid @RequestBody UpdateDonationItemStatusRequest request) {

        UpdateDonationItemStatusResponse response = donationService.changeStatusDonationItems(request);
        return ResponseEntity.ok(
                ApiResponseDTO.<UpdateDonationItemStatusResponse>builder()
                        .data(response)
                        .message("Cập Nhật Trạng Thái Vật Phẩm Trao Đổi Thành Công")
                        .statusCode(HttpStatus.OK.value())
                        .success(true)
                        .build());
    }


    @GetMapping("/items")
    @Operation(summary = "Get donation items with filters and pagination",
            description = "Retrieves donation items based on various filters and supports pagination.")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_STAFF', 'ROLE_STORE_MANAGER', 'ROLE_MANAGER')")
    public ResponseEntity<ApiResponseDTO<PageResponseDTO<DonationItemDetailResponse>>> getDonationItems(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String name,
            @RequestParam(required = false) Long donationId,
            @Parameter(description = "AT_EVENT, IN_WAREHOUSE, RECYCLED, LOST")
            @RequestParam(required = false )DonationItemStatus status,
            @RequestParam(required = false) Long eventId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @Parameter(description = "Sort field")
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @Parameter(description = "Sort direction (ASC/DESC)")
            @RequestParam(defaultValue = "DESC") String sortDir){

        Pageable pageable = PageRequest.of(
                page,
                size,
                Sort.by(Sort.Direction.fromString(sortDir), sortBy)
        );

        PageResponseDTO<DonationItemDetailResponse> donationItems = donationService.getDonationItems( code, name, donationId, status, eventId, pageable );


        return ResponseEntity.ok(
                ApiResponseDTO.<PageResponseDTO<DonationItemDetailResponse>>builder()
                        .data(donationItems)
                        .message("Lấy Danh Sách Vật Phẩm Trao Đổi Thành Công")
                        .statusCode(HttpStatus.OK.value())
                        .success(true)
                        .build());
    }

    @GetMapping("/export")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN','ROLE_MANAGER')")
    @Operation(summary = "Export Donations Data", description = "Export donations to Excel")
    public void exportDonations(
            @RequestParam(required = false) Long eventId,
            @RequestParam(required = false) Long userId,
            @RequestParam(required = false) DonationItemStatus itemStatus,
            @RequestParam(required = false) ConditionGrade conditionGrade,
            @RequestParam(required = false) Long categoryId,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime startDate,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime endDate,
            @RequestParam(defaultValue = "true") boolean includeItems,
            HttpServletResponse response) throws IOException {

        try {
            List<DonationExportDTO> exportData = donationService.getExportData(
                    eventId, userId, itemStatus, conditionGrade, categoryId,
                    startDate, endDate, includeItems);

            ExcelExportUtil.prepareExcelResponse(response, "donations_export");

            try (Workbook workbook = ExcelExportUtil.createWorkbook()) {
                Sheet sheet = ExcelExportUtil.createSheet(workbook, "Donations");

                // Create header
                ExcelExportUtil.createHeaderRow(sheet,
                        "ID Trao Đổi", "Mã Đơn Trao Đổi", "ID Người Dùng", "ID Sự Kiện", "Mã Sự Kiện", "Tên Sự Kiện",
                        "Ghi Chú Trao Đổi", "Người Kiểm Tra", "Tên Người Kiểm Tra", "Thời Gian Tạo",
                        "ID Vật Phẩm", "Mã Vật Phẩm", "Tên Vật Phẩm", "Mô Tả Vật Phẩm", "Tên Danh Mục",
                        "Mức Độ Tình Trạng", "Giá Trị Điểm Eco", "Trạng Thái Vật Phẩm", "ID Sản Phẩm Chuyển Đổi", "Đường Dẫn Hình Ảnh");

                // Write data
                int rowNum = 1;
                for (DonationExportDTO dto : exportData) {
                    Row row = sheet.createRow(rowNum++);
                    int colNum = 0;

                    row.createCell(colNum++).setCellValue(dto.getDonationId() != null ? dto.getDonationId() : "");
                    row.createCell(colNum++).setCellValue(dto.getDonationCode() != null ? dto.getDonationCode() : "");
                    row.createCell(colNum++).setCellValue(dto.getUserId() != null ? dto.getUserId() : "");
                    row.createCell(colNum++).setCellValue(dto.getEventId() != null ? dto.getEventId() : "");
                    row.createCell(colNum++).setCellValue(dto.getEventCode() != null ? dto.getEventCode() : "");
                    row.createCell(colNum++).setCellValue(dto.getEventName() != null ? dto.getEventName() : "");
                    row.createCell(colNum++).setCellValue(dto.getDonationNote() != null ? dto.getDonationNote() : "");
                    row.createCell(colNum++).setCellValue(dto.getInspectedBy() != null ? dto.getInspectedBy() : "");
                    row.createCell(colNum++).setCellValue(dto.getInspectorName() != null ? dto.getInspectorName() : "");
                    row.createCell(colNum++).setCellValue(dto.getDonationCreatedAt() != null ? dto.getDonationCreatedAt() : "");
                    row.createCell(colNum++).setCellValue(dto.getItemId() != null ? dto.getItemId() : "");
                    row.createCell(colNum++).setCellValue(dto.getItemCode() != null ? dto.getItemCode() : "");
                    row.createCell(colNum++).setCellValue(dto.getItemName() != null ? dto.getItemName() : "");
                    row.createCell(colNum++).setCellValue(dto.getItemDescription() != null ? dto.getItemDescription() : "");
                    row.createCell(colNum++).setCellValue(dto.getCategoryName() != null ? dto.getCategoryName() : "");
                    row.createCell(colNum++).setCellValue(dto.getConditionGrade() != null ? dto.getConditionGrade() : "");
                    row.createCell(colNum++).setCellValue(dto.getEcoPointValue() != null ? dto.getEcoPointValue() : "");
                    row.createCell(colNum++).setCellValue(dto.getItemStatus() != null ? dto.getItemStatus() : "");
                    row.createCell(colNum++).setCellValue(dto.getConvertProductId() != null ? dto.getConvertProductId() : "");
                    row.createCell(colNum++).setCellValue(dto.getImageUrl() != null ? dto.getImageUrl() : "");
                }

                workbook.write(response.getOutputStream());
            }
        } catch (Exception e) {
            log.error("Error exporting donations data", e);
            ExcelExportUtil.handleError(response, "Lỗi khi xuất dữ liệu trao đổi.");
        }
    }
}
