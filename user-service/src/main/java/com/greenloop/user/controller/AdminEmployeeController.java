package com.greenloop.user.controller;

import com.greenloop.user.dto.request.CreateEmployeeRequest;
import com.greenloop.user.dto.request.UpdateEmployeeRequest;
import com.greenloop.user.dto.response.ApiResponseDTO;
import com.greenloop.user.dto.response.EmployeeResponse;
import com.greenloop.user.service.AdminEmployeeService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
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
    @Operation(
            summary = "Get employee list",
            description = "Retrieve paginated list of employees with optional search and filter"
    )
    public ResponseEntity<ApiResponseDTO<Page<EmployeeResponse>>> getEmployees(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(required = false) String search,
            @RequestParam(required = false) String status,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "DESC") String sortDir
    ) {
        Pageable pageable = PageRequest.of(page, size,
                Sort.by(Sort.Direction.fromString(sortDir), sortBy));
        Page<EmployeeResponse> employees = adminEmployeeService.getEmployees(
                search, status, pageable);
        return ResponseEntity.ok(
                ApiResponseDTO.success("Lấy danh sách nhân viên thành công", employees, HttpStatus.OK)
        );
    }

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(
            summary = "Create new employee",
            description = "Create a new employee with MANAGER or STAFF role and optional avatar"
    )
    public ResponseEntity<ApiResponseDTO<EmployeeResponse>> createEmployee(
            @Valid @RequestPart("request") CreateEmployeeRequest request,
            @RequestPart(value = "avatar", required = false) MultipartFile avatar) {
        EmployeeResponse response = adminEmployeeService.createEmployee(request, avatar);
        return ResponseEntity.status(HttpStatus.CREATED).body(
                ApiResponseDTO.success("Tạo nhân viên thành công", response, HttpStatus.CREATED)
        );
    }


    @GetMapping("/{id}")
    @Operation(
            summary = "Get employee detail",
            description = "Retrieve employee information by ID"
    )
    public ResponseEntity<ApiResponseDTO<EmployeeResponse>> getEmployeeById(
            @PathVariable Long id) {
        EmployeeResponse response = adminEmployeeService.getEmployeeById(id);
        return ResponseEntity.ok(
                ApiResponseDTO.success("Lấy thông tin nhân viên thành công", response, HttpStatus.OK)
        );
    }

    @PutMapping(value = "/{id}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(
            summary = "Update employee information",
            description = "Update employee details and optional avatar by ID"
    )
    public ResponseEntity<ApiResponseDTO<EmployeeResponse>> updateEmployee(
            @PathVariable Long id,
            @Valid @RequestPart("request") UpdateEmployeeRequest request,
            @RequestPart(value = "avatar", required = false) MultipartFile avatar) {
        EmployeeResponse response = adminEmployeeService.updateEmployee(id, request, avatar);
        return ResponseEntity.ok(
                ApiResponseDTO.success("Cập nhật thông tin nhân viên thành công", response, HttpStatus.OK)
        );
    }



}
