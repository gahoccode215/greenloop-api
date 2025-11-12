package com.greenloop.product.controller;

import com.greenloop.product.dto.response.ApiResponseDTO;
import com.greenloop.product.dto.response.PageResponseDTO;
import com.greenloop.product.dto.response.ProductResponse;
import com.greenloop.product.service.ProductService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/products")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Product Controller", description = "APIs for product management")
public class ProductController {

    private final ProductService productService;

    @GetMapping
    @Operation(
            summary = "Get product list",
            description = "Retrieve paginated list of products with search and filter options"
    )
    public ResponseEntity<ApiResponseDTO<PageResponseDTO<ProductResponse>>> getProducts(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @Parameter(description = "Search by name, code, or description")
            @RequestParam(required = false) String search,
            @Parameter(description = "Filter by status (PENDING, AVAILABLE, SOLD, UNAVAILABLE)")
            @RequestParam(required = false) String status,
            @Parameter(description = "Filter by type (DONATION, PURCHASE)")
            @RequestParam(required = false) String type,
            @Parameter(description = "Filter by category ID")
            @RequestParam(required = false) Long categoryId,
            @Parameter(description = "Sort field")
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @Parameter(description = "Sort direction (ASC/DESC)")
            @RequestParam(defaultValue = "DESC") String sortDir) {

        log.info("Getting products - page: {}, size: {}, search: {}, status: {}, type: {}, categoryId: {}",
                page, size, search, status, type, categoryId);

        Pageable pageable = PageRequest.of(
                page,
                size,
                Sort.by(Sort.Direction.fromString(sortDir), sortBy)
        );

        PageResponseDTO<ProductResponse> products = productService.getProducts(
                search,
                status,
                type,
                categoryId,
                pageable
        );

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy danh sách sản phẩm thành công",
                        products,
                        HttpStatus.OK
                )
        );
    }

    @GetMapping("/{id}")
    @Operation(
            summary = "Get product detail",
            description = "Retrieve detail information of a product by ID"
    )
    public ResponseEntity<ApiResponseDTO<ProductResponse>> getProductDetail(
            @PathVariable Long id) {

        log.info("Getting product detail for id: {}", id);

        ProductResponse product = productService.getProductDetail(id);

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Lấy chi tiết sản phẩm thành công",
                        product,
                        HttpStatus.OK
                )
        );
    }
}
