package com.greenloop.product.controller;

import com.greenloop.product.dto.response.*;
import com.greenloop.product.service.DashboardService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/products/dashboard")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Product Dashboard Controller", description = "APIs for product dashboard statistics")
public class DashboardController {

    private final DashboardService productDashboardService;

    @GetMapping("/products")
    @Operation(summary = "Get product statistics", description = "Retrieves various statistics related to products.")
    @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<ApiResponseDTO<ProductStatisticsResponse>> getProductStatistics() {
        log.info("Received request to get product statistics");
        return ResponseEntity.ok(
                ApiResponseDTO.<ProductStatisticsResponse>builder()
                        .data(productDashboardService.getProductStatistics())
                        .message("Product statistics fetched successfully")
                        .statusCode(HttpStatus.OK.value())
                        .success(true)
                        .build()
        );
    }

    @GetMapping("/categories")
    @Operation(summary = "Get category statistics", description = "Retrieves various statistics related to categories.")
    @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<ApiResponseDTO<CategoryStatisticsResponse>> getCategoryStatistics() {
        log.info("Received request to get category statistics");
        return ResponseEntity.ok(
                ApiResponseDTO.<CategoryStatisticsResponse>builder()
                        .data(productDashboardService.getCategoryStatistics())
                        .message("Category statistics fetched successfully")
                        .statusCode(HttpStatus.OK.value())
                        .success(true)
                        .build()
        );
    }

    @GetMapping("/donations")
    @Operation(summary = "Get donation statistics", description = "Retrieves various statistics related to donations.")
    @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<ApiResponseDTO<DonationStatisticsResponse>> getDonationStatistics() {
        log.info("Received request to get donation statistics");
        return ResponseEntity.ok(
                ApiResponseDTO.<DonationStatisticsResponse>builder()
                        .data(productDashboardService.getDonationStatistics())
                        .message("Donation statistics fetched successfully")
                        .statusCode(HttpStatus.OK.value())
                        .success(true)
                        .build()
        );
    }

    @GetMapping("/event-mappings")
    @Operation(summary = "Get event product mapping statistics", description = "Retrieves various statistics related to event product mappings.")
    @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')")
    public ResponseEntity<ApiResponseDTO<EventProductMappingStatisticsResponse>> getEventProductMappingStatistics() {
        log.info("Received request to get event product mapping statistics");
        return ResponseEntity.ok(
                ApiResponseDTO.<EventProductMappingStatisticsResponse>builder()
                        .data(productDashboardService.getEventProductMappingStatistics())
                        .message("Event product mapping statistics fetched successfully")
                        .statusCode(HttpStatus.OK.value())
                        .success(true)
                        .build()
        );
    }
}
