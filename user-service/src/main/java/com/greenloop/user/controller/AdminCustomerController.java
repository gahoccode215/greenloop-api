package com.greenloop.user.controller;

import com.greenloop.user.dto.request.UpdateCustomerRequest;
import com.greenloop.user.dto.response.ApiResponseDTO;
import com.greenloop.user.dto.response.CustomerResponse;
import com.greenloop.user.dto.response.PageResponseDTO;
import com.greenloop.user.service.AdminCustomerService;
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
  public ResponseEntity<ApiResponseDTO<PageResponseDTO<CustomerResponse>>> getCustomers(
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "10") int size,
      @RequestParam(required = false) String search,
      @RequestParam(required = false) String status,
      @RequestParam(defaultValue = "createdAt") String sortBy,
      @RequestParam(defaultValue = "DESC") String sortDir) {

    Pageable pageable =
        PageRequest.of(page, size, Sort.by(Sort.Direction.fromString(sortDir), sortBy));

    PageResponseDTO<CustomerResponse> customers =
        adminCustomerService.getCustomers(search, status, pageable);

    return ResponseEntity.ok(
        ApiResponseDTO.success("Lấy danh sách khách hàng thành công", customers, HttpStatus.OK));
  }

  @GetMapping("/{id}")
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF', 'STORE_MANAGER')")
  public ResponseEntity<ApiResponseDTO<CustomerResponse>> getCustomerDetail(@PathVariable Long id) {
    CustomerResponse customer = adminCustomerService.getCustomerDetail(id);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Lấy chi tiết khách hàng thành công", customer, HttpStatus.OK));
  }

  @PatchMapping("/{id}/status")
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
  public ResponseEntity<ApiResponseDTO<CustomerResponse>> changeCustomerStatus(
      @PathVariable Long id, @RequestParam Boolean isActive) {

    CustomerResponse customer = adminCustomerService.changeCustomerStatus(id, isActive);

    return ResponseEntity.ok(
        ApiResponseDTO.success(
            "Thay đổi trạng thái khách hàng thành công", customer, HttpStatus.OK));
  }

  @PutMapping("/{id}")
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER', 'STAFF', 'STORE_MANAGER')")
  public ResponseEntity<ApiResponseDTO<CustomerResponse>> updateCustomer(
      @PathVariable Long id, @Valid @RequestBody UpdateCustomerRequest request) {
    CustomerResponse updated = adminCustomerService.updateCustomer(id, request);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Cập nhật khách hàng thành công", updated, HttpStatus.OK));
  }
}
