package com.greenloop.product.service;

import com.greenloop.product.dto.request.*;
import com.greenloop.product.dto.response.EventProductMappingExportDTO;
import com.greenloop.product.dto.response.PageResponseDTO;
import com.greenloop.product.dto.response.ProductExportDTO;
import com.greenloop.product.dto.response.ProductResponse;
import com.greenloop.product.enums.ConditionGrade;
import com.greenloop.product.enums.EventMappingStatus;
import com.greenloop.product.enums.ProductStatus;
import com.greenloop.product.enums.ProductType;
import org.springframework.data.domain.Pageable;
import org.springframework.web.multipart.MultipartFile;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

public interface ProductService {

    PageResponseDTO<ProductResponse> getProducts(
            String search,
            String status,
            String type,
            Long categoryId,
            Pageable pageable
    );

    ProductResponse getProductDetail(Long id);

    Long createProduct(CreateProductRequest request, List<MultipartFile> files);

    Long updateProduct(Long id, UpdateProductRequest request);

    void toggleStatusProduct(Long id);

    Long updateProductImages(Long productAssetId, MultipartFile files);

    void deActiveProductAsset(Long productAssetId);

    void addProductImages(Long productId, List<MultipartFile> files);

    void assignProductsToEvent(AssignProductEventRequest request);
    void changeProductEventStatus(
            UpdateStatusProductEventMappingRequest eventMappingRequest);
    void removeProductFromEvent(
            Long eventId,
            List<Long> productIds);

    List<ProductResponse> getProductAssignableToEvent(Long eventId);

    void updateProductStatus(Long productId, String newStatus);
    void updateProductEventMappingStatus(Long productId, Long eventId, EventMappingStatus status);

    List<ProductExportDTO> getExportData(
            ProductStatus status,
            ProductType type,
            ConditionGrade conditionGrade,
            Long categoryId,
            Long donationItemId,
            LocalDateTime startDate,
            LocalDateTime endDate,
            BigDecimal minPrice,
            BigDecimal maxPrice
    );

    List<EventProductMappingExportDTO> getExportData(
            Long eventId,
            Long productId,
            EventMappingStatus mappingStatus,
            ProductStatus productStatus,
            LocalDateTime startDate,
            LocalDateTime endDate
    );

}
