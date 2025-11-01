package com.greenloop.user.controller;

import com.greenloop.user.dto.request.CreateEmployeeRequest;
import com.greenloop.user.dto.request.UpdateEmployeeRequest;
import com.greenloop.user.dto.response.ApiResponseDTO;
import com.greenloop.user.dto.response.CreateEmployeeResponse;
import com.greenloop.user.dto.response.EmployeeResponse;
import com.greenloop.user.dto.response.PageResponseDTO;
import com.greenloop.user.service.AdminEmployeeService;
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
//    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    @Operation(
            summary = "Get employee list",
            description = "Retrieve paginated list of employees. ADMIN can view STAFF and MANAGER, MANAGER can only view STAFF")
    public ResponseEntity<ApiResponseDTO<PageResponseDTO<EmployeeResponse>>> getEmployees(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @Parameter(description = "Search by email, full name, or phone number")
            @RequestParam(required = false) String search,
            @Parameter(description = "Filter by active status (true/false)")
            @RequestParam(required = false) String status,
            @Parameter(description = "Sort field")
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @Parameter(description = "Sort direction (ASC/DESC)")
            @RequestParam(defaultValue = "DESC") String sortDir) {

        log.info("Getting employees - page: {}, size: {}, search: {}, status: {}",
                page, size, search, status);

        Pageable pageable = PageRequest.of(page, size,
                Sort.by(Sort.Direction.fromString(sortDir), sortBy));

        PageResponseDTO<EmployeeResponse> employees =
                adminEmployeeService.getEmployees(search, status, pageable);

        log.info("Retrieved {} employees out of {} total",
                employees.getContent().size(), employees.getTotalElements());

        return ResponseEntity.ok(
                ApiResponseDTO.success("Lấy danh sách nhân viên thành công", employees, HttpStatus.OK));
    }

    @GetMapping("/{id}")
//    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    @Operation(
            summary = "Get employee detail",
            description = "Retrieve detail information of an employee by id")
    public ResponseEntity<ApiResponseDTO<EmployeeResponse>> getEmployeeDetail(@PathVariable Long id) {
        log.info("Getting employee detail for id: {}", id);
        EmployeeResponse employee = adminEmployeeService.getEmployeeDetail(id);
        return ResponseEntity.ok(
                ApiResponseDTO.success("Lấy chi tiết nhân viên thành công", employee, HttpStatus.OK));
    }

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
//    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    @Operation(
            summary = "Create new employee",
            description = "Create new employee account with optional avatar")
    public ResponseEntity<ApiResponseDTO<CreateEmployeeResponse>> createEmployee(
            @Valid @RequestPart("request") CreateEmployeeRequest request,
            @RequestPart(value = "avatar", required = false) MultipartFile avatar) {
        log.info("Creating new employee with role: {}", request.getRole());
        CreateEmployeeResponse response = adminEmployeeService.createEmployee(request, avatar);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponseDTO.success("Tạo tài khoản nhân viên thành công", response, HttpStatus.CREATED));
    }

    @PutMapping(value = "/{id}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
//    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    @Operation(
            summary = "Update employee",
            description = "Update employee information with optional avatar")
    public ResponseEntity<ApiResponseDTO<EmployeeResponse>> updateEmployee(
            @PathVariable Long id,
            @Valid @RequestPart("request") UpdateEmployeeRequest request,
            @RequestPart(value = "avatar", required = false) MultipartFile avatar) {
        log.info("Updating employee with id: {}", id);
        EmployeeResponse response = adminEmployeeService.updateEmployee(id, request, avatar);
        return ResponseEntity.ok(
                ApiResponseDTO.success("Cập nhật thông tin nhân viên thành công", response, HttpStatus.OK));
    }

    @PatchMapping("/{id}/status")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    @Operation(
            summary = "Change employee status",
            description = "Activate or deactivate employee account. ADMIN can change STAFF and MANAGER status, MANAGER can only change STAFF status")
    public ResponseEntity<ApiResponseDTO<EmployeeResponse>> changeEmployeeStatus(
            @PathVariable Long id,
            @RequestParam Boolean isActive) {
        log.info("Changing status for employee with id: {} to: {}", id, isActive);
        EmployeeResponse response = adminEmployeeService.changeEmployeeStatus(id, isActive);
        String message = response.getIsActive()
                ? "Kích hoạt tài khoản nhân viên thành công"
                : "Vô hiệu hóa tài khoản nhân viên thành công";
        return ResponseEntity.ok(ApiResponseDTO.success(message, response, HttpStatus.OK));
    }

}
