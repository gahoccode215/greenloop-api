package com.greenloop.product.service.impl;

import com.greenloop.product.dto.response.PageResponseDTO;
import com.greenloop.product.dto.response.ProductResponse;
import com.greenloop.product.entity.Product;
import com.greenloop.product.entity.ProductAsset;
import com.greenloop.product.enums.ProductStatus;
import com.greenloop.product.enums.ProductType;
import com.greenloop.product.exception.ProductNotFoundException;
import com.greenloop.product.repository.ProductRepository;
import com.greenloop.product.service.ProductService;
import com.greenloop.product.utils.PageResponseUtil;
import jakarta.persistence.criteria.Predicate;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class ProductServiceImpl implements ProductService {

    private final ProductRepository productRepository;

    @Override
    public PageResponseDTO<ProductResponse> getProducts(
            String search,
            String status,
            String type,
            Long categoryId,
            Pageable pageable) {

        log.info("Getting products - search: {}, status: {}, type: {}, categoryId: {}",
                search, status, type, categoryId);

        Specification<Product> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            // Search by name or code
            if (search != null && !search.isEmpty()) {
                String searchPattern = "%" + search.toLowerCase() + "%";
                predicates.add(
                        cb.or(
                                cb.like(cb.lower(root.get("name")), searchPattern),
                                cb.like(cb.lower(root.get("code")), searchPattern),
                                cb.like(cb.lower(root.get("description")), searchPattern)
                        )
                );
            }

            // Filter by status
            if (status != null && !status.isEmpty()) {
                try {
                    ProductStatus productStatus = ProductStatus.valueOf(status.toUpperCase());
                    predicates.add(cb.equal(root.get("status"), productStatus));
                } catch (IllegalArgumentException e) {
                    log.warn("Invalid status value: {}", status);
                }
            }

            // Filter by type
            if (type != null && !type.isEmpty()) {
                try {
                    ProductType productType = ProductType.valueOf(type.toUpperCase());
                    predicates.add(cb.equal(root.get("type"), productType));
                } catch (IllegalArgumentException e) {
                    log.warn("Invalid type value: {}", type);
                }
            }

            // Filter by category
            if (categoryId != null) {
                predicates.add(cb.equal(root.get("category").get("id"), categoryId));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };

        Page<Product> page = productRepository.findAll(spec, pageable);

        Page<ProductResponse> productPage = page.map(this::mapProductToProductResponse);

        PageResponseDTO<ProductResponse> response = PageResponseUtil.toPageResponse(productPage);

        log.info("Retrieved {} products out of {} total",
                response.getContent().size(),
                response.getTotalElements());

        return response;
    }

    @Override
    public ProductResponse getProductDetail(Long id) {
        log.info("Getting product detail for id: {}", id);

        Product product = productRepository.findById(id)
                .orElseThrow(() -> new ProductNotFoundException("Không tìm thấy sản phẩm với ID: " + id));

        return mapProductToProductResponse(product);
    }

    private ProductResponse mapProductToProductResponse(Product product) {
        return ProductResponse.builder()
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
                .conditionGrade(product.getConditionGrade())
                .imageUrls(product.getAssets() != null
                        ? product.getAssets().stream()
                        .map(ProductAsset::getImageUrl)
                        .filter(url -> url != null && !url.isEmpty())
                        .collect(Collectors.toList())
                        : List.of())
                .weight(product.getWeight())
                .length(product.getLength())
                .width(product.getWidth())
                .height(product.getHeight())
                .createdAt(product.getCreatedAt())
                .updatedAt(product.getUpdatedAt())
                .build();
    }

}
