package com.greenloop.product.service.impl;

import com.greenloop.product.dto.request.AssignProductEventRequest;
import com.greenloop.product.dto.request.CreateProductRequest;
import com.greenloop.product.dto.request.EcoPointInfoRequest;
import com.greenloop.product.dto.request.UpdateProductRequest;
import com.greenloop.product.dto.response.EcoPointResponse;
import com.greenloop.product.dto.response.EventResponse;
import com.greenloop.product.dto.response.PageResponseDTO;
import com.greenloop.product.dto.response.ProductResponse;
import com.greenloop.product.entity.*;
import com.greenloop.product.enums.*;
import com.greenloop.product.exception.BusinessException;
import com.greenloop.product.exception.ProductNotFoundException;
import com.greenloop.product.repository.*;
import com.greenloop.product.service.*;
import com.greenloop.product.utils.PageResponseUtil;
import jakarta.persistence.criteria.Predicate;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class ProductServiceImpl implements ProductService {

    private final ProductRepository productRepository;
    private final String ecoPointRedisKey = "eco_point_rule_";
    private final CacheService cacheService;
    private final RewardServiceFeign rewardServiceFeign;
    private static final AtomicLong counter = new AtomicLong();
    private final CategoryRepository categoryRepository;
    private final DonationItemRepository donationItemRepository;
    private final ProductAssetRepository productAssetRepository;
    private final EventProductMappingRepository eventProductMappingRepository;
    private final CloudinaryService cloudinaryService;
    private final String localImagePath = "GreenLoop/Products";
    private final EventServiceFeign eventServiceFeign;


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
    @Override
    @Transactional
    public void updateProductStatus(Long productId, String newStatus) {
        log.info("Updating product {} to status: {}", productId, newStatus);

        Product product = productRepository.findById(productId)
                .orElseThrow(() -> new ProductNotFoundException(
                        "Không tìm thấy sản phẩm với ID: " + productId));

        ProductStatus status = ProductStatus.valueOf(newStatus);
        product.setStatus(status);
        productRepository.save(product);

        log.info("Successfully updated product {} to status: {}", productId, newStatus);
    }

    @Override
    @Transactional
    public Long createProduct(CreateProductRequest request, List<MultipartFile> files) {

        validateEcoPointRule(request);

        String code = randomCodeDonationItemCode(request.getCategoryId().toString());

        Category category = categoryRepository.findById(request.getCategoryId())
                .orElseThrow(() -> new BusinessException(ErrorCode.CATEGORY_NOT_FOUND));

        DonationItem donation = donationItemRepository.findByCode(request.getDonationItemCode())
                .orElseThrow(() -> new BusinessException(ErrorCode.DONATION_ITEM_NOT_FOUND));


        Product product = Product.builder()
                .code(code)
                .name(request.getProductName())
                .description(request.getDescription())
                .price(request.getPrice())
                .ecoPointValue(request.getEcoPointValue())
                .conditionGrade(request.getConditionGrade())
                .donationItemId(donation.getId())
                .type(request.getType())
                .status(ProductStatus.AVAILABLE)
                .category(category)
                .build();

        product = productRepository.save(product);


        if (files != null) {
            for (MultipartFile file : files) {
                if (!file.isEmpty()) {

                    ProductAsset asset = handleImageUpload(file);

                    product.addProductAsset(asset);
                }
            }
        }
        productRepository.save(product);
        donation.setConvertProductId(product.getId());
        donation.setStatus(DonationItemStatus.RECYCLED);
        donationItemRepository.save(donation);
        return product.getId();
    }

    @Override
    @Transactional
    public Long updateProduct(Long id, UpdateProductRequest request) {
        Product product = productRepository.findById(id).orElseThrow(() -> new BusinessException(ErrorCode.PRODUCT_NOT_FOUND));

        if (request.getEcoPointValue() != null && !product.getEcoPointValue().equals(request.getEcoPointValue())) {
            validateEcoPointRuleUpdate(request);
            product.setEcoPointValue(request.getEcoPointValue());
        }
        if (request.getProductName() != null) {
            product.setName(request.getProductName());
        }
        if (request.getDescription() != null) {
            product.setDescription(request.getDescription());
        }
        if (request.getPrice() != null) {
            product.setPrice(request.getPrice());
        }
        if (request.getConditionGrade() != null) {
            product.setConditionGrade(request.getConditionGrade());
        }
        if (request.getStatus() != null) {
            product.setStatus(request.getStatus());
        }
        if (request.getType() != null) {
            product.setType(request.getType());
        }
        Long currentUserId = getCurrentUserId();
        product.setUpdatedBy(currentUserId);
        productRepository.save(product);

        return product.getId();
    }

    @Override
    public void toggleStatusProduct(Long id) {
        Product product = productRepository.findById(id)
                .orElseThrow(() -> new BusinessException(ErrorCode.PRODUCT_NOT_FOUND));
        product.setIsActive(!product.getIsActive());
        Long currentUserId = getCurrentUserId();
        product.setUpdatedBy(currentUserId);
        productRepository.save(product);
    }

    @Override
    public Long updateProductImages(Long productAssetId, MultipartFile files) {
        ProductAsset productAsset = productAssetRepository.findById(productAssetId)
                .orElseThrow(() -> new BusinessException(ErrorCode.PRODUCT_ASSET_NOT_FOUND));
        ProductAsset newAsset = handleImageUpload(files);
        productAsset.setMediaKey(newAsset.getMediaKey());
        productAsset.setImageUrl(newAsset.getImageUrl());
        productAssetRepository.save(productAsset);
        return productAsset.getId();
    }

    @Override
    public void deActiveProductAsset(Long productAssetId) {
        ProductAsset productAsset = productAssetRepository.findById(productAssetId)
                .orElseThrow(() -> new BusinessException(ErrorCode.PRODUCT_ASSET_NOT_FOUND));
        productAsset.setIsActive(false);
        productAssetRepository.save(productAsset);
    }

    @Override
    public void addProductImages(Long productId, List<MultipartFile> files) {
        Product product = productRepository.findById(productId)
                .orElseThrow(() -> new BusinessException(ErrorCode.PRODUCT_NOT_FOUND));
        if (files != null) {
            for (MultipartFile file : files) {
                if (!file.isEmpty()) {

                    ProductAsset asset = handleImageUpload(file);
                    asset.setProduct(product);
                    productAssetRepository.save(asset);
                }
            }
        }
    }

    @Override
    public void assignProductsToEvent(AssignProductEventRequest request) {

        EventResponse eventInfo = eventServiceFeign.getInfoEventId(request.getEventId());
        if (eventInfo == null) {
            throw new BusinessException(ErrorCode.EVENT_NOT_FOUND);
        }

        LocalDateTime displayFrom = request.getDisplayFrom();
        LocalDateTime displayTo = request.getDisplayTo();

        for (Long productId : request.getProductIds()) {

            List<EventProductMapping> overlaps =
                    eventProductMappingRepository.findOverlappingAssignments(
                            productId,
                            request.getEventId(),
                            displayFrom,
                            displayTo
                    );

            if (!overlaps.isEmpty()) {
                throw new BusinessException(
                        ErrorCode.EVENT_PRODUCT_TIME_CONFLICT
                );
            }
        }
        for (Long productId : request.getProductIds()) {
            EventProductMapping mapping = EventProductMapping.builder()
                    .eventId(request.getEventId())
                    .productId(
                            productRepository.findById(productId)
                                    .orElseThrow(() -> new BusinessException(ErrorCode.PRODUCT_NOT_FOUND))
                    )
                    .displayFrom(displayFrom)
                    .displayTo(displayTo)
                    .status(EventMappingStatus.DISPLAYED)
                    .build();

            eventProductMappingRepository.save(mapping);
        }

    }

    @Override
    public void removeProductFromEvent(List<Long> eventProductMappingId) {
        for (Long mappingId : eventProductMappingId) {
            EventProductMapping mapping = eventProductMappingRepository.findById(mappingId)
                    .orElseThrow(() -> new BusinessException(ErrorCode.EVENT_PRODUCT_MAPPING_NOT_FOUND));
            eventProductMappingRepository.delete(mapping);
        }
    }

    @Override
    public List<ProductResponse> getProductAssignableToEvent(Long eventId) {
        List<EventProductMapping> assignedMappings =
                eventProductMappingRepository.findByEventId(eventId);
        List<ProductResponse> productResponses = new ArrayList<>();
        for (EventProductMapping mapping : assignedMappings) {
            Product product = mapping.getProductId();
            productResponses.add(mapProductToProductResponse(product));
        }
        return productResponses;
    }


    private ProductAsset handleImageUpload(MultipartFile file) {
        try {
            Map<String, String> accessKey =
                    cloudinaryService.uploadImage(file.getBytes(), localImagePath);

            return ProductAsset.builder()
                    .mediaKey(accessKey.get("public_id"))
                    .imageUrl(cloudinaryService.getImageUrl(accessKey.get("asset_id")))
                    .build();

        } catch (Exception e) {
            throw new BusinessException(ErrorCode.UPLOAD_IMAGE_ERROR);
        }
    }


    private String randomCodeDonationItemCode(String categoryId) {
        LocalDateTime now = LocalDateTime.now();
        String datePart = now.format(DateTimeFormatter.ofPattern("ddMMyy"));

        long seq = counter.getAndIncrement();
        String seqPart = String.format("%06d", seq % 1_000_000);

        return "GL_PRO_" + categoryId + "_" + datePart + "_" + seqPart;
    }

    private void validateEcoPointRuleUpdate(UpdateProductRequest itemReq) {
        String redisKey = ecoPointRedisKey + EcoActionType.RESALE + "_" + itemReq.getCategoryId();
        EcoPointResponse ecoPointRule = cacheService.get(redisKey, EcoPointResponse.class);
        if (ecoPointRule == null) {
            ecoPointRule = rewardServiceFeign.getEcoPoint(EcoPointInfoRequest.builder().ecoActionType(EcoActionType.RESALE).categoryId(itemReq.getCategoryId()).build());
        }

        if (ecoPointRule == null) {
            log.warn("Eco point rule for action type DONATION and category ID {} not found", itemReq.getCategoryId());
        }

        if (itemReq.getEcoPointValue() < ecoPointRule.getMinPoints() || itemReq.getEcoPointValue() > ecoPointRule.getMaxPoints()) {
            log.warn("Eco point value {} is out of bounds for category ID {}", itemReq.getEcoPointValue(), itemReq.getCategoryId());
            throw new BusinessException(ErrorCode.ECO_POINT_VALUE_OUT_OF_BOUNDS);
        }
    }


    private void validateEcoPointRule(CreateProductRequest itemReq) {
        String redisKey = ecoPointRedisKey + EcoActionType.RESALE + "_" + itemReq.getCategoryId();
        EcoPointResponse ecoPointRule = cacheService.get(redisKey, EcoPointResponse.class);
        if (ecoPointRule == null) {
            ecoPointRule = rewardServiceFeign.getEcoPoint(EcoPointInfoRequest.builder().ecoActionType(EcoActionType.RESALE).categoryId(itemReq.getCategoryId()).build());
        }

        if (ecoPointRule == null) {
            log.warn("Eco point rule for action type DONATION and category ID {} not found", itemReq.getCategoryId());
        }

        if (itemReq.getEcoPointValue() < ecoPointRule.getMinPoints() || itemReq.getEcoPointValue() > ecoPointRule.getMaxPoints()) {
            log.warn("Eco point value {} is out of bounds for category ID {}", itemReq.getEcoPointValue(), itemReq.getCategoryId());
            throw new BusinessException(ErrorCode.ECO_POINT_VALUE_OUT_OF_BOUNDS);
        }
    }

    private Long getCurrentUserId() {
        return Long.valueOf(
                SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
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
