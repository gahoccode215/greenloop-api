package com.greenloop.product.service;

import com.greenloop.product.dto.request.AssignProductEventRequest;
import com.greenloop.product.dto.request.CreateProductRequest;
import com.greenloop.product.dto.request.UpdateProductRequest;
import com.greenloop.product.dto.response.PageResponseDTO;
import com.greenloop.product.dto.response.ProductResponse;
import org.springframework.data.domain.Pageable;
import org.springframework.web.multipart.MultipartFile;

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

    void removeProductFromEvent(
            Long eventId,
            List<Long> productIds);

    List<ProductResponse> getProductAssignableToEvent(Long eventId);

    void updateProductStatus(Long productId, String newStatus);
}
