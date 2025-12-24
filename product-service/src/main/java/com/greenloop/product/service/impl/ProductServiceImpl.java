package com.greenloop.product.service.impl;

import com.greenloop.product.dto.request.*;
import com.greenloop.product.dto.response.*;
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
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
    private final EventServiceFeign eventServiceFeign;


    @Override
    public PageResponseDTO<ProductResponse> getProducts(
            String search,
            String status,
            String type,
            Long categoryId,
            Pageable pageable) {

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

            if (type != null && !type.isEmpty()) {
                try {
                    ProductType productType = ProductType.valueOf(type.toUpperCase());
                    predicates.add(cb.equal(root.get("type"), productType));
                } catch (IllegalArgumentException e) {
                    log.warn("Invalid type value: {}", type);
                }
            }

            if (categoryId != null) {
                predicates.add(cb.equal(root.get("category").get("id"), categoryId));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };

        Page<Product> page = productRepository.findAll(spec, pageable);

        Page<ProductResponse> productPage = page.map(this::mapProductToProductResponse);

        PageResponseDTO<ProductResponse> response = PageResponseUtil.toPageResponse(productPage);

        return response;
    }

    private boolean calculateEventFlag(Product product) {

        if (product.getEventMappings() == null || product.getEventMappings().isEmpty())
            return false;

        EventProductMapping active = product.getEventMappings()
                .stream()
                .filter(m -> m.getStatus() == EventMappingStatus.PREPARED
                        || m.getStatus() == EventMappingStatus.DISPLAYED)
                .findFirst()
                .orElse(null);

        if (active == null) return false;

        LocalDateTime displayFrom = active.getDisplayFrom();
        if (displayFrom == null) return false;

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime limit = displayFrom.minusDays(1);
        return now.isAfter(displayFrom)
                && (active.getDisplayTo() == null || now.isBefore(active.getDisplayTo()));

    }


    @Override
    public ProductResponse getProductDetail(Long id) {
        Product product = productRepository.findById(id)
                .orElseThrow(() -> new ProductNotFoundException("Không tìm thấy sản phẩm với ID: " + id));
        return mapProductToProductResponse(product);
    }

    @Override
    @Transactional
    public void updateProductStatus(Long productId, String newStatus) {
        Product product = productRepository.findById(productId)
                .orElseThrow(() -> new ProductNotFoundException(
                        "Không tìm thấy sản phẩm với ID: " + productId));
        ProductStatus status = ProductStatus.valueOf(newStatus);
        product.setStatus(status);
        productRepository.save(product);
    }
    @Override
    @Transactional
    public void updateProductEventMappingStatus(Long productId, Long eventId, EventMappingStatus status) {
        EventProductMapping mapping = eventProductMappingRepository
                .findByEventIdAndProductId(eventId, productId)
                .orElseThrow(() -> new BusinessException(
                        "Không tìm thấy mapping sản phẩm trong sự kiện. Event ID: " + eventId + ", Product ID: " + productId,
                        ErrorCode.EVENT_PRODUCT_MAPPING_NOT_FOUND
                ));

        mapping.setStatus(status);
        eventProductMappingRepository.save(mapping);
    }


    @Override
    @Transactional
    public Long createProduct(CreateProductRequest request, List<MultipartFile> files) {

        validateEcoPointRule(request);

        String code = randomCodeDonationItemCode(request.getCategoryId().toString());

        Category category = categoryRepository.findById(request.getCategoryId())
                .orElseThrow(() -> new BusinessException("Không tìm thấy Category Id: " + request.getCategoryId(), ErrorCode.CATEGORY_NOT_FOUND));

        DonationItem donation = donationItemRepository.findByCode(request.getDonationItemCode())
                .orElseThrow(() -> new BusinessException("Không tìm thấy Donation Code: " + request.getDonationItemCode(), ErrorCode.DONATION_ITEM_NOT_FOUND));

        if (donation.getConvertProductId() != null) {
            throw new BusinessException(ErrorCode.DONATION_ITEM_ALREADY_CONVERTED);
        }


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
        Product product = productRepository.findById(id)
                .orElseThrow(() ->
                        new BusinessException(
                                "Không tìm thấy sản phẩm với ID: " + id,
                                ErrorCode.PRODUCT_NOT_FOUND
                        )
                );


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
                .orElseThrow(() ->
                        new BusinessException(
                                "Không tìm thấy sản phẩm với ID: " + id,
                                ErrorCode.PRODUCT_NOT_FOUND
                        )
                );

        product.setIsActive(!product.getIsActive());
        Long currentUserId = getCurrentUserId();
        product.setUpdatedBy(currentUserId);
        productRepository.save(product);
    }

    @Override
    public Long updateProductImages(Long productAssetId, MultipartFile files) {
        ProductAsset productAsset = productAssetRepository.findById(productAssetId)
                .orElseThrow(() ->
                        new BusinessException(
                                "Không tìm thấy Product Asset với ID: " + productAssetId,
                                ErrorCode.PRODUCT_ASSET_NOT_FOUND
                        )
                );

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
                .orElseThrow(() ->
                        new BusinessException(
                                "Không tìm thấy sản phẩm với ID: " + productId,
                                ErrorCode.PRODUCT_NOT_FOUND
                        )
                );

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

        EventResponse eventInfo = null;
        try {
            eventInfo = eventServiceFeign.getInfoEventId(request.getEventId());
        } catch (Exception e) {
            log.error("Error fetching event info for event ID {}: {}", request.getEventId(), e.getMessage());
            throw new BusinessException("Lỗi khi lấy thông tin sự kiện với ID: " + request.getEventId(), ErrorCode.EVENT_SERVICE_ERROR);
        }
        if (eventInfo == null) {
            throw new BusinessException("Không tìm thấy sự kiện với ID: " + request.getEventId(), ErrorCode.EVENT_NOT_FOUND);

        }


        LocalDateTime displayFrom = eventInfo.getStartTime();
        LocalDateTime displayTo = eventInfo.getEndTime();

        for (Long productId : request.getProductIds()) {

            boolean alreadyExists =
                    eventProductMappingRepository.existsByEventIdAndProductId(
                            request.getEventId(), productId
                    );

            if (alreadyExists) {
                throw new BusinessException("Sản phẩm ID " + productId +
                        " đã được gắn tại sự kiện: " + eventInfo.getName(), ErrorCode.EVENT_PRODUCT_ALREADY_EXISTS);
            }

            List<EventProductMapping> overlaps =
                    eventProductMappingRepository.findOverlappingAssignments(
                            productId,
                            request.getEventId(),
                            displayFrom,
                            displayTo
                    );

            if (!overlaps.isEmpty()) {
                throw new BusinessException(
                        "Sản phẩm bị trùng thời gian với sự kiện khác",
                        ErrorCode.EVENT_PRODUCT_TIME_CONFLICT
                );
            }
        }
        for (Long productId : request.getProductIds()) {
            EventProductMapping mapping = EventProductMapping.builder()
                    .eventId(request.getEventId())
                    .product(
                            productRepository.findById(productId)
                                    .orElseThrow(() ->
                                            new BusinessException(
                                                    "Không tìm thấy sản phẩm với ID: " + productId,
                                                    ErrorCode.PRODUCT_NOT_FOUND
                                            ))
                    )
                    .displayFrom(displayFrom)
                    .displayTo(displayTo)
                    .status(EventMappingStatus.ASSIGNED)
                    .build();

            eventProductMappingRepository.save(mapping);
        }

    }

    @Override
    @Transactional
    public void changeProductEventStatus(UpdateStatusProductEventMappingRequest eventMappingRequest) {
        for (Long productId : eventMappingRequest.getProductIds()) {
            EventProductMapping mapping =
                    eventProductMappingRepository.findByEventIdAndProductId(eventMappingRequest.getEventId(), productId)
                            .orElseThrow(() ->
                                    new BusinessException(
                                            "Không tìm thấy mapping sản phẩm trong sự kiện. Event ID: " + eventMappingRequest.getEventId() + ", Product ID: " + productId,
                                            ErrorCode.EVENT_PRODUCT_MAPPING_NOT_FOUND
                                    )
                            );

            mapping.setStatus(eventMappingRequest.getStatus());
            eventProductMappingRepository.save(mapping);
        }
    }

    @Override
    @Transactional
    public void removeProductFromEvent(Long eventId, List<Long> productIds) {
        for (Long productId : productIds) {
            EventProductMapping mapping =
                    eventProductMappingRepository.findByEventIdAndProductId(eventId, productId)
                            .orElseThrow(() ->
                                    new BusinessException(
                                            "Không tìm thấy mapping sản phẩm trong sự kiện. Event ID: " + eventId + ", Product ID: " + productId,
                                            ErrorCode.EVENT_PRODUCT_MAPPING_NOT_FOUND
                                    )
                            );

            eventProductMappingRepository.delete(mapping);
        }
    }

    @Override
    public List<ProductResponse> getProductAssignableToEvent(Long eventId) {
        List<EventProductMapping> assignedMappings =
                eventProductMappingRepository.findByEventId(eventId);
        List<ProductResponse> productResponses = new ArrayList<>();
        for (EventProductMapping mapping : assignedMappings) {
            Product product = mapping.getProduct();
            productResponses.add(mapProductToProductResponse(product));
        }
        return productResponses;
    }



    private ProductAsset handleImageUpload(MultipartFile file) {
        try {
            String localImagePath = "GreenLoop/Products";
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
        try {
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
                throw new BusinessException(
                        "Giá trị Eco Point " + itemReq.getEcoPointValue() + " không hợp lệ cho Category ID " + itemReq.getCategoryId(),
                        ErrorCode.ECO_POINT_VALUE_OUT_OF_BOUNDS
                );
            }
        } catch (Exception e) {
            log.error("Error validating eco point rule: {}", e.getMessage());
            throw new BusinessException(
                    "Lỗi khi xác thực quy tắc Eco Point",
                    ErrorCode.ECO_POINT_RULE_NOT_FOUND
            );
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

//        if(ecoPointRule.getIsActive() == null || !ecoPointRule.getIsActive()) {
//            log.warn("Eco point rule for action type DONATION and category ID {} is inactive", itemReq.getCategoryId());
//            throw new BusinessException(
//                    "Quy tắc Eco Point không hoạt động. Vui lòng chọn eco point bạn cảm thấy phù hợp hoặc liên hệ Admin.",
//                    ErrorCode.ECO_POINT_RULE_INACTIVE
//            );
//        }

        if (itemReq.getEcoPointValue() < ecoPointRule.getMinPoints() || itemReq.getEcoPointValue() > ecoPointRule.getMaxPoints()) {
            log.warn("Eco point value {} is out of bounds for category ID {}", itemReq.getEcoPointValue(), itemReq.getCategoryId());
            throw new BusinessException(
                    "Giá trị Eco Point " + itemReq.getEcoPointValue() + " không hợp lệ cho Category ID " + itemReq.getCategoryId(),
                    ErrorCode.ECO_POINT_VALUE_OUT_OF_BOUNDS
            );
        }
    }

    private Long getCurrentUserId() {
        return Long.valueOf(
                SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
    }

    private ProductResponse mapProductToProductResponse(Product product) {
        DonationItem donationItem = null;
        if (product.getDonationItemId() != null) {
            donationItem = donationItemRepository.findById(product.getDonationItemId()).orElse(null);
        }

        Boolean eventFlag = null;
        try {
            eventFlag = calculateEventFlag(product);
        } catch (Exception e) {
            log.error("Error calculating event flag for product ID {}: {}", product.getId(), e.getMessage());
        }

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
                .donationItemCode(donationItem != null ? donationItem.getCode() : null)
                .eventProductMappingResponses(mapEventMappings(product))
                .conditionGrade(product.getConditionGrade())
                .imageUrls(mapProductAssetsToResponses(product.getAssets()))
                .weight(product.getWeight())
                .length(product.getLength())
                .width(product.getWidth())
                .height(product.getHeight())
                .createdAt(product.getCreatedAt())
                .updatedAt(product.getUpdatedAt())
                .isEventReadyForSelling(eventFlag)
                .build();
    }

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
                        .build()
                ).toList();
    }


    private List<ProductAssetResponse> mapProductAssetsToResponses(Set<ProductAsset> assets) {
        return assets.stream()
                .map(asset -> ProductAssetResponse.builder()
                        .productAssetId(asset.getId())
                        .productAssetUrl(asset.getImageUrl())
                        .build())
                .collect(Collectors.toList());
    }


    @Override
    public List<ProductExportDTO> getExportData(
            ProductStatus status,
            ProductType type,
            ConditionGrade conditionGrade,
            Long categoryId,
            Long donationItemId,
            LocalDateTime startDate,
            LocalDateTime endDate,
            BigDecimal minPrice,
            BigDecimal maxPrice) {

        Specification<Product> spec = (root, query, cb) -> {
            List<jakarta.persistence.criteria.Predicate> predicates = new ArrayList<>();

            if (status != null) {
                predicates.add(cb.equal(root.get("status"), status));
            }
            if (type != null) {
                predicates.add(cb.equal(root.get("type"), type));
            }
            if (conditionGrade != null) {
                predicates.add(cb.equal(root.get("conditionGrade"), conditionGrade));
            }
            if (categoryId != null) {
                predicates.add(cb.equal(root.get("category").get("id"), categoryId));
            }
            if (donationItemId != null) {
                predicates.add(cb.equal(root.get("donationItemId"), donationItemId));
            }
            if (startDate != null && endDate != null) {
                predicates.add(cb.between(root.get("createdAt"), startDate, endDate));
            }
            if (minPrice != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("price"), minPrice));
            }
            if (maxPrice != null) {
                predicates.add(cb.lessThanOrEqualTo(root.get("price"), maxPrice));
            }

            return cb.and(predicates.toArray(new jakarta.persistence.criteria.Predicate[0]));
        };

        List<Product> products = productRepository.findAll(spec);
        DateTimeFormatter dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

        return products.stream().map(product -> {
            // Get donation item code if exists
            String donationCode = "";
            if (product.getDonationItemId() != null) {
                try {
                    DonationItem item = donationItemRepository.findById(product.getDonationItemId())
                            .orElse(null);
                    if (item != null && item.getDonation() != null) {
                        donationCode = item.getDonation().getCode();
                    }
                } catch (Exception e) {
                    log.error("Error fetching donation item: {}", product.getDonationItemId(), e);
                }
            }

            String imageUrls = product.getAssets().stream()
                    .map(ProductAsset::getImageUrl)
                    .collect(Collectors.joining("; "));

            return ProductExportDTO.builder()
                    .productId(String.valueOf(product.getId()))
                    .productCode(product.getCode())
                    .productName(product.getName())
                    .description(product.getDescription() != null ? product.getDescription() : "")
                    .categoryName(product.getCategory() != null ? product.getCategory().getName() : "")
                    .donationItemId(product.getDonationItemId() != null ?
                            String.valueOf(product.getDonationItemId()) : "")
                    .donationCode(donationCode)
                    .price(product.getPrice() != null ? product.getPrice().toString() : "")
                    .ecoPointValue(product.getEcoPointValue() != null ?
                            String.valueOf(product.getEcoPointValue()) : "")
                    .conditionGrade(product.getConditionGrade() != null ?
                            product.getConditionGrade().name() : "")
                    .status(product.getStatus().name())
                    .type(product.getType().name())
                    .createdAt(product.getCreatedAt().format(dateFormatter))
                    .updatedAt(product.getUpdatedAt().format(dateFormatter))
                    .imageUrls(imageUrls)
                    .build();
        }).collect(Collectors.toList());
    }

    @Override
    public List<EventProductMappingExportDTO> getExportData(
            Long eventId,
            Long productId,
            EventMappingStatus mappingStatus,
            ProductStatus productStatus,
            LocalDateTime startDate,
            LocalDateTime endDate) {

        Specification<EventProductMapping> spec = (root, query, cb) -> {
            List<jakarta.persistence.criteria.Predicate> predicates = new ArrayList<>();

            if (eventId != null) {
                predicates.add(cb.equal(root.get("eventId"), eventId));
            }
            if (productId != null) {
                predicates.add(cb.equal(root.get("product").get("id"), productId));
            }
            if (mappingStatus != null) {
                predicates.add(cb.equal(root.get("status"), mappingStatus));
            }
            if (productStatus != null) {
                predicates.add(cb.equal(root.get("product").get("status"), productStatus));
            }
            if (startDate != null && endDate != null) {
                predicates.add(cb.between(root.get("displayFrom"), startDate, endDate));
            }

            return cb.and(predicates.toArray(new jakarta.persistence.criteria.Predicate[0]));
        };
        Sort sort = Sort.by(Sort.Direction.DESC, "createdAt");
        List<EventProductMapping> mappings = eventProductMappingRepository.findAll(spec, sort);
        DateTimeFormatter dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

        return mappings.stream().map(mapping -> {
            Product product = mapping.getProduct();

            // Get event info
            EventResponse event = null;
            try {
                event = eventServiceFeign.getInfoEventId(mapping.getEventId());
            } catch (Exception e) {
                log.error("Error fetching event: {}", mapping.getEventId(), e);
            }

            return EventProductMappingExportDTO.builder()
                    .mappingId(String.valueOf(mapping.getId()))
                    .eventId(String.valueOf(mapping.getEventId()))
                    .eventCode(event != null ? event.getCode() : "")
                    .eventName(event != null ? event.getName() : "")
                    .eventStartTime(event != null && event.getStartTime() != null ?
                            event.getStartTime().format(dateFormatter) : "")
                    .eventEndTime(event != null && event.getEndTime() != null ?
                            event.getEndTime().format(dateFormatter) : "")
                    .eventStatus(event != null ? event.getStatus().name() : "")
                    .productId(String.valueOf(product.getId()))
                    .productCode(product.getCode())
                    .productName(product.getName())
                    .productPrice(product.getPrice() != null ? product.getPrice().toString() : "")
                    .productStatus(product.getStatus().name())
                    .productType(product.getType().name())
                    .categoryName(product.getCategory() != null ? product.getCategory().getName() : "")
                    .displayFrom(mapping.getDisplayFrom() != null ?
                            mapping.getDisplayFrom().format(dateFormatter) : "")
                    .displayTo(mapping.getDisplayTo() != null ?
                            mapping.getDisplayTo().format(dateFormatter) : "")
                    .mappingStatus(mapping.getStatus().name())
                    .createdAt(mapping.getCreatedAt().format(dateFormatter))
                    .build();
        }).collect(Collectors.toList());
    }

}
