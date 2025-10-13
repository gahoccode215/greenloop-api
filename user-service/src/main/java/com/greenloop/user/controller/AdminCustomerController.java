package com.greenloop.user.controller;

import com.greenloop.user.dto.response.ApiResponseDTO;
import com.greenloop.user.dto.response.CustomerResponse;
import com.greenloop.user.service.AdminCustomerService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/admin/customers")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Admin Customer Controller", description = "APIs for admin customer management")
public class AdminCustomerController {

    private final AdminCustomerService adminCustomerService;

    @GetMapping
    @Operation(
            summary = "Get customer list",
            description = "Retrieve paginated list of customers with optional search and filter"
    )
    public ResponseEntity<ApiResponseDTO<Page<CustomerResponse>>> getCustomers(
            @RequestParam(defaultValue = "0") int page,

            @RequestParam(defaultValue = "10") int size,

            @Parameter(description = "Search by email, first name, last name, or phone number")
            @RequestParam(required = false) String search,

            @Parameter(description = "Filter by active status (true/false)")
            @RequestParam(required = false) String status,

            @Parameter(description = "Sort field")
            @RequestParam(defaultValue = "createdAt") String sortBy,

            @Parameter(description = "Sort direction (ASC/DESC)")
            @RequestParam(defaultValue = "DESC") String sortDir
    ) {
        log.info("Getting customers - page: {}, size: {}, search: {}, status: {}",
                page, size, search, status);

        Pageable pageable = PageRequest.of(page, size,
                Sort.by(Sort.Direction.fromString(sortDir), sortBy));

        Page<CustomerResponse> customers = adminCustomerService.getCustomers(
                search, status, pageable);

        log.info("Retrieved {} customers out of {} total",
                customers.getNumberOfElements(), customers.getTotalElements());

        return ResponseEntity.ok(
                ApiResponseDTO.success("Lấy danh sách khách hàng thành công", customers, HttpStatus.OK)
        );
    }
}
