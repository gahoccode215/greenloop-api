package com.greenloop.product.service.impl;

import com.greenloop.product.dto.request.MarkProductsSoldRequest;
import com.greenloop.product.dto.request.ReserveProductsRequest;
import com.greenloop.product.dto.request.UnreserveProductsRequest;
import com.greenloop.product.dto.request.UpdateProductStatusRequest;
import com.greenloop.product.dto.response.EventProductMappingResponse;
import com.greenloop.product.dto.response.ProductAssetResponse;
import com.greenloop.product.dto.response.ProductResponse;
import com.greenloop.product.entity.DonationItem;
import com.greenloop.product.entity.EventProductMapping;
import com.greenloop.product.entity.Product;
import com.greenloop.product.entity.ProductAsset;
import com.greenloop.product.enums.ErrorCode;
import com.greenloop.product.enums.EventMappingStatus;
import com.greenloop.product.enums.ProductStatus;
import com.greenloop.product.exception.BusinessException;
import com.greenloop.product.exception.ProductNotFoundException;
import com.greenloop.product.repository.DonationItemRepository;
import com.greenloop.product.repository.EventProductMappingRepository;
import com.greenloop.product.repository.ProductRepository;
import com.greenloop.product.service.ProductInternalService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class ProductInternalServiceImpl implements ProductInternalService {

    private final ProductRepository productRepository;
    private final EventProductMappingRepository eventProductMappingRepository;
    private final DonationItemRepository donationItemRepository;

    @Override
    public void validateProductsForOfflineOrder(Long eventId, List<Long> productIds) {
        log.info("Validating {} products for offline order at event {}", productIds.size(), eventId);

        for (Long productId : productIds) {
            Product product = productRepository.findById(productId)
                    .orElseThrow(() -> new ProductNotFoundException(
                            "Không tìm thấy sản phẩm với ID: " + productId));

            if (product.getStatus() == ProductStatus.SOLD) {
                throw new BusinessException(
                        "Sản phẩm " + product.getName() + " đã được bán",
                        ErrorCode.PRODUCT_ALREADY_SOLD
                );
            }

            if (product.getStatus() != ProductStatus.AVAILABLE) {
                throw new BusinessException(
                        "Sản phẩm " + product.getName() + " không khả dụng. Trạng thái hiện tại: " + product.getStatus(),
                        ErrorCode.PRODUCT_NOT_AVAILABLE
                );
            }

            EventProductMapping mapping = eventProductMappingRepository
                    .findByEventIdAndProductId(eventId, productId)
                    .orElseThrow(() -> new BusinessException(
                            "Sản phẩm " + product.getName() + " không được gán vào sự kiện này",
                            ErrorCode.PRODUCT_NOT_IN_EVENT
                    ));

            LocalDateTime now = LocalDateTime.now();

            if (mapping.getDisplayFrom() != null && now.isBefore(mapping.getDisplayFrom())) {
                throw new BusinessException(
                        "Sản phẩm " + product.getName() + " chưa đến thời gian hiển thị tại sự kiện",
                        ErrorCode.PRODUCT_NOT_YET_DISPLAYABLE
                );
            }

            if (mapping.getDisplayTo() != null && now.isAfter(mapping.getDisplayTo())) {
                throw new BusinessException(
                        "Sản phẩm " + product.getName() + " đã hết thời gian hiển thị tại sự kiện",
                        ErrorCode.PRODUCT_DISPLAY_EXPIRED
                );
            }

            if (mapping.getStatus() != EventMappingStatus.DISPLAYED) {
                throw new BusinessException(
                        "Sản phẩm " + product.getName() + " không được hiển thị tại sự kiện. Trạng thái: " + mapping.getStatus(),
                        ErrorCode.PRODUCT_NOT_DISPLAYED
                );
            }

            log.debug("Product {} validated successfully for event {}", productId, eventId);
        }

        log.info("All {} products validated successfully for event {}", productIds.size(), eventId);
    }

    @Override
    public ProductResponse getProductById(Long productId) {
        log.info("Fetching product details for productId: {}", productId);

        // 1. Lấy Product entity
        Product product = productRepository.findById(productId)
                .orElseThrow(() -> new ProductNotFoundException(
                        "Không tìm thấy sản phẩm với ID: " + productId));

        // 2. Lấy DonationItem nếu có
        DonationItem donationItem = null;
        if (product.getDonationItemId() != null) {
            donationItem = donationItemRepository.findById(product.getDonationItemId())
                    .orElse(null);
        }

        // 3. Map sang ProductResponse
        ProductResponse response = ProductResponse.builder()
                .id(product.getId())
                .code(product.getCode())
                .name(product.getName())
                .description(product.getDescription())
                .price(product.getPrice())
                .ecoPointValue(product.getEcoPointValue())
                .conditionGrade(product.getConditionGrade())
                .status(product.getStatus())
                .type(product.getType())
                .categoryId(product.getCategory() != null ? product.getCategory().getId() : null)
                .categoryName(product.getCategory() != null ? product.getCategory().getName() : null)
                .donationItemId(product.getDonationItemId())
                .donationItemCode(donationItem != null ? donationItem.getCode() : null)
                .eventProductMappingResponses(mapEventMappings(product))
                .imageUrls(mapProductAssets(product.getAssets()))
                .weight(product.getWeight())
                .length(product.getLength())
                .width(product.getWidth())
                .height(product.getHeight())
                .createdAt(product.getCreatedAt())
                .updatedAt(product.getUpdatedAt())
                .build();

        log.debug("Product details fetched successfully: id={}, name={}, ecoPointValue={}",
                product.getId(), product.getName(), product.getEcoPointValue());

        return response;
    }
    @Override
    @Transactional
    public void reserveProducts(ReserveProductsRequest request) {
        log.info("Reserving {} products for order {}",
                request.getProducts().size(), request.getOrderId());

        for (ReserveProductsRequest.ProductReserve item : request.getProducts()) {
            Product product = productRepository.findById(item.getProductId())
                    .orElseThrow(() -> new ProductNotFoundException(
                            "Không tìm thấy sản phẩm với ID: " + item.getProductId()));

            if (product.getStatus() != ProductStatus.AVAILABLE) {
                throw new BusinessException(
                        "Sản phẩm " + product.getCode() + " không ở trạng thái AVAILABLE",
                        ErrorCode.PRODUCT_NOT_AVAILABLE
                );
            }

            product.setStatus(ProductStatus.RESERVED);
            productRepository.save(product);

            log.info("Product {} reserved for order {}",
                    product.getCode(), request.getOrderId());
        }
    }

    @Override
    @Transactional
    public void unreserveProducts(UnreserveProductsRequest request) {
        log.info("Unreserving {} products for cancelled order {}",
                request.getProducts().size(), request.getOrderId());

        for (UnreserveProductsRequest.ProductUnreserve item : request.getProducts()) {
            Product product = productRepository.findById(item.getProductId())
                    .orElseThrow(() -> new ProductNotFoundException(
                            "Không tìm thấy sản phẩm với ID: " + item.getProductId()));

            if (product.getStatus() == ProductStatus.RESERVED) {
                product.setStatus(ProductStatus.AVAILABLE);
                productRepository.save(product);

                log.info("Product {} unreserved back to AVAILABLE",
                        product.getCode());
            } else {
                log.warn("Product {} is not RESERVED, current status: {}",
                        product.getCode(), product.getStatus());
            }
        }
    }

    @Override
    @Transactional
    public void markProductsAsSold(MarkProductsSoldRequest request) {
        log.info("Marking {} products as SOLD for completed order {}",
                request.getProducts().size(), request.getOrderId());

        for (MarkProductsSoldRequest.ProductSold item : request.getProducts()) {
            Product product = productRepository.findById(item.getProductId())
                    .orElseThrow(() -> new ProductNotFoundException(
                            "Không tìm thấy sản phẩm với ID: " + item.getProductId()));

            if (product.getStatus() == ProductStatus.RESERVED) {
                product.setStatus(ProductStatus.SOLD);
                productRepository.save(product);

                log.info("Product {} marked as SOLD", product.getCode());
            } else {
                log.warn("Product {} is not RESERVED, current status: {}",
                        product.getCode(), product.getStatus());
            }
        }
    }

    /**
     * Map Event Mappings sang DTO
     */
    private List<EventProductMappingResponse> mapEventMappings(Product product) {
        LocalDateTime now = LocalDateTime.now();

        return product.getEventMappings().stream()
                .filter(m -> m.getDisplayTo() == null || m.getDisplayTo().isAfter(now))
                .map(m -> EventProductMappingResponse.builder()
                        .id(m.getId())
                        .eventId(m.getEventId())
                        .displayFrom(m.getDisplayFrom())
                        .displayTo(m.getDisplayTo())
                        .status(m.getStatus())
                        .build())
                .collect(Collectors.toList());
    }
    @Override
    @Transactional
    public void updateProductStatus(UpdateProductStatusRequest request) {
        log.info("Updating status for {} products in order {}",
                request.getProductUpdates().size(), request.getOrderCode());

        for (UpdateProductStatusRequest.ProductStatusUpdate update : request.getProductUpdates()) {
            Product product = productRepository.findById(update.getProductId())
                    .orElseThrow(() -> new ProductNotFoundException(
                            "Không tìm thấy sản phẩm với ID: " + update.getProductId()));

            // Validate old status (warning only, không block)
            if (!product.getStatus().name().equals(update.getOldStatus())) {
                log.warn("Product {} current status {} does not match expected old status {}",
                        product.getCode(), product.getStatus(), update.getOldStatus());
            }

            // Update to new status
            ProductStatus newStatus = ProductStatus.valueOf(update.getNewStatus());
            product.setStatus(newStatus);
            productRepository.save(product);

            log.info("Updated product {} from {} to {}",
                    product.getCode(), update.getOldStatus(), update.getNewStatus());
        }

        log.info("Successfully updated status for {} products in order {}",
                request.getProductUpdates().size(), request.getOrderCode());
    }


    /**
     * Map ProductAssets sang DTO
     */
    private List<ProductAssetResponse> mapProductAssets(Set<ProductAsset> assets) {
        if (assets == null) {
            return List.of();
        }

        return assets.stream()
                .filter(ProductAsset::getIsActive) // Chỉ lấy asset active
                .map(asset -> ProductAssetResponse.builder()
                        .productAssetId(asset.getId())
                        .productAssetUrl(asset.getImageUrl())
                        .build())
                .collect(Collectors.toList());
    }
}
