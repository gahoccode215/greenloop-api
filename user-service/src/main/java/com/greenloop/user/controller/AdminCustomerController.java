package com.greenloop.user.controller;

import com.greenloop.user.dto.response.ApiResponseDTO;
import com.greenloop.user.dto.response.CustomerResponse;
import com.greenloop.user.dto.response.PageResponseDTO;
import com.greenloop.user.service.AdminCustomerService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/admin/customers")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Admin Customer Controller", description = "APIs for admin customer management")
public class AdminCustomerController {

  private final AdminCustomerService adminCustomerService;

  @GetMapping
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF', 'STORE_MANAGER')")
  @Operation(
      summary = "Get customer list",
      description = "Retrieve paginated list of customers with search and filter options")
  public ResponseEntity<ApiResponseDTO<PageResponseDTO<CustomerResponse>>> getCustomers(
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "10") int size,
      @Parameter(description = "Search by email, full name, or phone number")
          @RequestParam(required = false)
          String search,
      @Parameter(description = "Filter by active status (true/false)")
          @RequestParam(required = false)
          String status,
      @Parameter(description = "Sort field") @RequestParam(defaultValue = "createdAt")
          String sortBy,
      @Parameter(description = "Sort direction (ASC/DESC)") @RequestParam(defaultValue = "DESC")
          String sortDir) {

    log.info(
        "Getting customers - page: {}, size: {}, search: {}, status: {}",
        page,
        size,
        search,
        status);

    Pageable pageable =
        PageRequest.of(page, size, Sort.by(Sort.Direction.fromString(sortDir), sortBy));

    PageResponseDTO<CustomerResponse> customers =
        adminCustomerService.getCustomers(search, status, pageable);

    return ResponseEntity.ok(
        ApiResponseDTO.success("Lấy danh sách khách hàng thành công", customers, HttpStatus.OK));
  }

  @GetMapping("/{id}")
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF', 'STORE_MANAGER')")
  @Operation(
      summary = "Get customer detail",
      description = "Retrieve detail information of a customer by id")
  public ResponseEntity<ApiResponseDTO<CustomerResponse>> getCustomerDetail(@PathVariable Long id) {
    log.info("Getting customer detail for id: {}", id);
    CustomerResponse customer = adminCustomerService.getCustomerDetail(id);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Lấy chi tiết khách hàng thành công", customer, HttpStatus.OK));
  }

    @PatchMapping("/{id}/status")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    @Operation(
            summary = "Change customer status",
            description = "Change active status of a customer account")
    public ResponseEntity<ApiResponseDTO<CustomerResponse>> changeCustomerStatus(
            @PathVariable Long id,
            @RequestParam Boolean isActive) {

        log.info("Changing customer status for id: {}, new status: {}", id, isActive);

        CustomerResponse customer = adminCustomerService.changeCustomerStatus(id, isActive);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Thay đổi trạng thái khách hàng thành công", customer, HttpStatus.OK));
    }

}
