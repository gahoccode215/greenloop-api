package com.greenloop.product.controller;

import com.greenloop.product.dto.request.AssignProductEventRequest;
import com.greenloop.product.dto.request.CreateProductRequest;
import com.greenloop.product.dto.request.UpdateProductRequest;
import com.greenloop.product.dto.request.UpdateStatusProductEventMappingRequest;
import com.greenloop.product.dto.response.ApiResponseDTO;
import com.greenloop.product.dto.response.PageResponseDTO;
import com.greenloop.product.dto.response.ProductResponse;
import com.greenloop.product.enums.EventMappingStatus;
import com.greenloop.product.service.ProductService;
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

import java.util.List;

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


    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Create new product", description = "Create product with images upload")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_STAFF', 'ROLE_STORE_MANAGER', 'ROLE_MANAGER')")
    public ResponseEntity<ApiResponseDTO<Long>> createProduct(
            @RequestPart("product") @Valid CreateProductRequest request,
            @RequestPart(value = "thumbnail", required = false) List<MultipartFile> files) {

        log.info("Request to create product: {}", request);

        Long id = productService.createProduct(request, files);

        return ResponseEntity.ok(
                ApiResponseDTO.success("Tạo sản phẩm thành công", id, HttpStatus.CREATED)
        );
    }


    @PutMapping("/{id}")
    @Operation(summary = "Update product", description = "Update general info of product")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_STAFF', 'ROLE_STORE_MANAGER', 'ROLE_MANAGER')")
    public ResponseEntity<ApiResponseDTO<Long>> updateProduct(
            @PathVariable Long id,
            @Valid @RequestBody UpdateProductRequest request) {

        log.info("Update product id = {}, request = {}", id, request);

        Long result = productService.updateProduct(id, request);

        return ResponseEntity.ok(
                ApiResponseDTO.success("Cập nhật sản phẩm thành công", result, HttpStatus.OK)
        );
    }


    @PatchMapping("/{id}/toggle-status")
    @Operation(summary = "Toggle product status", description = "Switch product status between AVAILABLE / UNAVAILABLE")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_STAFF', 'ROLE_STORE_MANAGER', 'ROLE_MANAGER')")
    public ResponseEntity<ApiResponseDTO<String>> toggleStatusProduct(
            @PathVariable Long id) {

        log.info("Toggling status for product id: {}", id);

        productService.toggleStatusProduct(id);

        return ResponseEntity.ok(
                ApiResponseDTO.success("Cập nhật trạng thái sản phẩm thành công", null, HttpStatus.OK)
        );
    }


    @PutMapping(value = "/assets/{productAssetId}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Update a product image", description = "Replace a specific product image")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_STAFF', 'ROLE_STORE_MANAGER', 'ROLE_MANAGER')")
    public ResponseEntity<ApiResponseDTO<Long>> updateProductImage(
            @PathVariable Long productAssetId,
            @RequestPart MultipartFile file) {

        log.info("Updating image for asset id: {}", productAssetId);

        Long id = productService.updateProductImages(productAssetId, file);

        return ResponseEntity.ok(
                ApiResponseDTO.success("Cập nhật ảnh thành công", id, HttpStatus.OK)
        );
    }


    @DeleteMapping("/assets/{productAssetId}")
    @Operation(summary = "Deactivate product asset", description = "Disable an image of a product")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_STAFF', 'ROLE_STORE_MANAGER', 'ROLE_MANAGER')")
    public ResponseEntity<ApiResponseDTO<String>> deactivateProductAsset(
            @PathVariable Long productAssetId) {

        log.info("Deactivating product asset: {}", productAssetId);

        productService.deActiveProductAsset(productAssetId);

        return ResponseEntity.ok(
                ApiResponseDTO.success("Xoá ảnh sản phẩm thành công", null, HttpStatus.OK)
        );
    }


    @PostMapping(value = "/{productId}/assets", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Add product images", description = "Upload more images for a product")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_STAFF', 'ROLE_STORE_MANAGER', 'ROLE_MANAGER')")
    public ResponseEntity<ApiResponseDTO<String>> addProductImages(
            @PathVariable Long productId,
            @RequestPart List<MultipartFile> files) {

        log.info("Adding images to product id: {}, files: {}", productId, files.size());

        productService.addProductImages(productId, files);

        return ResponseEntity.ok(
                ApiResponseDTO.success("Thêm ảnh sản phẩm thành công", null, HttpStatus.CREATED)
        );
    }


    @PostMapping("/assign-to-event")
    @Operation(summary = "Assign products to event", description = "Bind product list to a specific event with display time")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_STAFF', 'ROLE_STORE_MANAGER', 'ROLE_MANAGER')")
    public ResponseEntity<ApiResponseDTO<String>> assignProductsToEvent(
            @Valid @RequestBody AssignProductEventRequest request) {

        log.info("Assign products to event: {}", request);

        productService.assignProductsToEvent(request);

        return ResponseEntity.ok(
                ApiResponseDTO.success("Gán sản phẩm vào sự kiện thành công", null, HttpStatus.OK)
        );
    }

    @PutMapping("/change-event-status-items")
    @Operation(summary = "Change product-event mapping status", description = "Update status of products in an event")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_MANAGER')")
    public ResponseEntity<ApiResponseDTO<String>> changeProductEventStatus(
            @RequestBody @Valid UpdateStatusProductEventMappingRequest request) {
        log.info("Change product event mapping status: {}", request);
        productService.changeProductEventStatus(request);
        return ResponseEntity.ok(
                ApiResponseDTO.success("Cập nhật trạng thái sản phẩm trong sự kiện thành công", null, HttpStatus.OK)
        );
    }


    @DeleteMapping("/remove-from-event/{eventId}")
    @Operation(summary = "Remove product-event mapping", description = "Deactivate product from event")
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_STAFF', 'ROLE_STORE_MANAGER', 'ROLE_MANAGER')")
    public ResponseEntity<ApiResponseDTO<String>> removeProductFromEvent(
            @PathVariable("eventId") Long eventId,
            @RequestBody List<Long> productIds) {

        log.info("Removing product-event mappings: {}", productIds);

        productService.removeProductFromEvent(eventId, productIds);

        return ResponseEntity.ok(
                ApiResponseDTO.success("Xoá sản phẩm khỏi sự kiện thành công", null, HttpStatus.OK)
        );
    }


    @GetMapping("/assignable-to-event/{eventId}")
    @Operation(summary = "Get products assignable to event", description = "Retrieve products that can be assigned to a specific event")
    public ResponseEntity<ApiResponseDTO<List<ProductResponse>>> getProductAssignableToEvent(
            @PathVariable Long eventId) {
        log.info("Getting products assignable to event id: {}", eventId);
        List<ProductResponse> products = productService.getProductAssignableToEvent(eventId);
        return ResponseEntity.ok(
                ApiResponseDTO.success("Lấy sản phẩm có thể gán vào sự kiện thành công", products, HttpStatus.OK)
        );
    }


}
