package com.greenloop.user.controller;

import com.greenloop.user.dto.request.CreateEmployeeRequest;
import com.greenloop.user.dto.request.UpdateEmployeeRequest;
import com.greenloop.user.dto.response.*;
import com.greenloop.user.service.AdminEmployeeService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/v1/admin/employees")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Admin Employee Controller", description = "APIs for admin employee management")
public class AdminEmployeeController {

  private final AdminEmployeeService adminEmployeeService;

  @GetMapping
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
  public ResponseEntity<ApiResponseDTO<PageResponseDTO<EmployeeResponse>>> getEmployees(
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "10") int size,
      @RequestParam(required = false) String search,
      @RequestParam(required = false) String status,
      @RequestParam(defaultValue = "createdAt") String sortBy,
      @RequestParam(defaultValue = "DESC") String sortDir) {
    Pageable pageable =
        PageRequest.of(page, size, Sort.by(Sort.Direction.fromString(sortDir), sortBy));

    PageResponseDTO<EmployeeResponse> employees =
        adminEmployeeService.getEmployees(search, status, pageable);

    return ResponseEntity.ok(
        ApiResponseDTO.success("Lấy danh sách nhân viên thành công", employees, HttpStatus.OK));
  }

  @GetMapping("/{id}")
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
  public ResponseEntity<ApiResponseDTO<EmployeeResponse>> getEmployeeDetail(@PathVariable Long id) {
    EmployeeResponse employee = adminEmployeeService.getEmployeeDetail(id);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Lấy chi tiết nhân viên thành công", employee, HttpStatus.OK));
  }

  @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
  public ResponseEntity<ApiResponseDTO<CreateEmployeeResponse>> createEmployee(
      @Valid @RequestPart("request") CreateEmployeeRequest request,
      @RequestPart(value = "avatar", required = false) MultipartFile avatar) {
    CreateEmployeeResponse response = adminEmployeeService.createEmployee(request, avatar);
    return ResponseEntity.status(HttpStatus.CREATED)
        .body(
            ApiResponseDTO.success(
                "Tạo tài khoản nhân viên thành công", response, HttpStatus.CREATED));
  }

  @PutMapping(value = "/{id}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
  public ResponseEntity<ApiResponseDTO<EmployeeResponse>> updateEmployee(
      @PathVariable Long id,
      @Valid @RequestPart("request") UpdateEmployeeRequest request,
      @RequestPart(value = "avatar", required = false) MultipartFile avatar) {
    EmployeeResponse response = adminEmployeeService.updateEmployee(id, request, avatar);
    return ResponseEntity.ok(
        ApiResponseDTO.success("Cập nhật thông tin nhân viên thành công", response, HttpStatus.OK));
  }

  @PatchMapping("/{id}/status")
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
  public ResponseEntity<ApiResponseDTO<EmployeeResponse>> changeEmployeeStatus(
      @PathVariable Long id, @RequestParam Boolean isActive) {
    EmployeeResponse response = adminEmployeeService.changeEmployeeStatus(id, isActive);
    String message =
        response.getIsActive()
            ? "Kích hoạt tài khoản nhân viên thành công"
            : "Vô hiệu hóa tài khoản nhân viên thành công";
    return ResponseEntity.ok(ApiResponseDTO.success(message, response, HttpStatus.OK));
  }

  @PostMapping("/{id}/reset-password")
  @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
  public ResponseEntity<ApiResponseDTO<ResetPasswordResponse>> resetEmployeePassword(
      @PathVariable Long id) {

    ResetPasswordResponse response = adminEmployeeService.resetEmployeePassword(id);

    return ResponseEntity.ok(
        ApiResponseDTO.success("Cấp lại mật khẩu thành công", response, HttpStatus.OK));
  }
}
