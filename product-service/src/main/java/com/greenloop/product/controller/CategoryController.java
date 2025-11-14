package com.greenloop.product.controller;


import com.greenloop.product.dto.request.CategoryRequest;
import com.greenloop.product.dto.response.ApiResponseDTO;
import com.greenloop.product.dto.response.CategoryResponse;
import com.greenloop.product.service.CategoryService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/categories")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Category Controller", description = "APIs for managing product categories")
public class CategoryController {

    private final CategoryService categoryService;

    @GetMapping
    @Operation(summary = "Get all categories", description = "Retrieves a list of all product categories.")
    public ResponseEntity<ApiResponseDTO<List<CategoryResponse>>> getCategories() {
        log.info("getCategories");
        List<CategoryResponse> categories = categoryService.getCategories();
        return ResponseEntity.ok(
                ApiResponseDTO.<List<CategoryResponse>>builder()
                        .data(categories)
                        .message("Categories retrieved successfully")
                        .statusCode(HttpStatus.OK.value())
                        .success(true)
                        .build()
        );
    }

    @PostMapping
    @Operation(summary = "Create a new category", description = "Creates a new product category.")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_MANAGER')")
    public ResponseEntity<ApiResponseDTO<Void>> createCategory(@RequestBody @Valid CategoryRequest categoryRequest) {
        log.info("createCategory");
        categoryService.createCategory(categoryRequest);
        return ResponseEntity.ok(
                ApiResponseDTO.<Void>builder()
                        .message("Category created successfully")
                        .statusCode(HttpStatus.OK.value())
                        .success(true)
                        .build()
        );
    }

    @PutMapping("/{categoryId}/active-status")
    @Operation(summary = "Update category active status", description = "Toggles the active status of a product category.")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_MANAGER')")
    public ResponseEntity<ApiResponseDTO<Void>> updateActiveStatus(@PathVariable Long categoryId) {
        log.info("updateActiveStatus for categoryId: {}", categoryId);
        categoryService.updateActiveStatus(categoryId);
        return ResponseEntity.ok(
                ApiResponseDTO.<Void>builder()
                        .message("Category active status updated successfully")
                        .statusCode(HttpStatus.OK.value())
                        .success(true)
                        .build()
        );
    }

    @PostMapping("/{categoryId}")
    @Operation(summary = "Update category", description = "Updates the details of a product category.")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_MANAGER')")
    public ResponseEntity<ApiResponseDTO<Void>> updateCategory(@PathVariable Long categoryId,
                                                               @RequestBody @Valid CategoryRequest categoryRequest) {
        log.info("updateCategory for categoryId: {}", categoryId);
        categoryService.updateCategory(categoryId, categoryRequest);
        return ResponseEntity.ok(
                ApiResponseDTO.<Void>builder()
                        .message("Category updated successfully")
                        .statusCode(HttpStatus.OK.value())
                        .success(true)
                        .build());
    }
}
