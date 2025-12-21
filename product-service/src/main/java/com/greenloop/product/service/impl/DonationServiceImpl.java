package com.greenloop.product.service.impl;

import com.greenloop.product.dto.event.EcoPointTransactionDTO;
import com.greenloop.product.dto.event.NotificationEvent;
import com.greenloop.product.dto.request.DonationCreateRequest;
import com.greenloop.product.dto.request.DonationItemCreateRequest;
import com.greenloop.product.dto.request.EcoPointInfoRequest;
import com.greenloop.product.dto.request.UpdateDonationItemStatusRequest;
import com.greenloop.product.dto.response.*;
import com.greenloop.product.entity.Category;
import com.greenloop.product.entity.Donation;
import com.greenloop.product.entity.DonationItem;
import com.greenloop.product.enums.*;
import com.greenloop.product.exception.BusinessException;
import com.greenloop.product.repository.CategoryRepository;
import com.greenloop.product.repository.DonationItemRepository;
import com.greenloop.product.repository.DonationRepository;
import com.greenloop.product.service.*;
import com.greenloop.product.utils.PageResponseUtil;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import jakarta.persistence.criteria.Predicate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class DonationServiceImpl implements DonationService {

    private final CloudinaryService cloudinaryService;
    private final RewardServiceFeign rewardServiceFeign;
    private final EventServiceFeign eventServiceFeign;
    private final UserServiceFeign userServiceFeign;
    private final CacheService cacheService;
    private final CategoryRepository categoryRepository;
    private final DonationRepository donationRepository;
    private final DonationItemRepository donationItemRepository;
    private final String localImagePath = "GreenLoop/Donations";
    private final String ecoPointRedisKey = "eco_point_rule_";
    private final EcoPointDonationProducer ecoPointDonationProducer;
    private final Map<Long, String> eventNameCache = new ConcurrentHashMap<>();
    private final NotificationProducer notificationProducer;



    private final String donationEcoPointBindingName = "ecoPointDonation-out-0";

    @Override
    @Transactional
    public Long createDonation(DonationCreateRequest request, List<MultipartFile> files) {
        Long currentUserId = getCurrentUserId();
        log.info("Create Donation by Current user ID: {}", currentUserId);

        Boolean isValidEventAndStaff = eventServiceFeign.validateStaffInEvent(request.getEventId(), currentUserId);
        if (!isValidEventAndStaff) {
            log.warn("User ID: {} is not assigned staff for Event ID: {}", currentUserId, request.getEventId());
            throw new BusinessException(ErrorCode.EVENT_OR_STAFF_NOT_VALID);
        }

        Donation donation = Donation.builder()
                .code(randomCodeDonationCode())
                .userId(request.getUserId())
                .eventId(request.getEventId())
                .totalWeight(request.getTotalWeight())
                .note(request.getNote())
                .inspectedBy(currentUserId)
                .build();

        List<DonationItem> items = new ArrayList<>();

        for (int i = 0; i < request.getDonationItems().size(); i++) {
            DonationItemCreateRequest itemReq = request.getDonationItems().get(i);
            MultipartFile imageFile = (files != null && i < files.size()) ? files.get(i) : null;
            Category category = categoryRepository.findById(itemReq.getCategoryId()).orElseThrow(
                    () -> new BusinessException(ErrorCode.CATEGORY_NOT_FOUND)
            );
            validateEcoPointRule(itemReq);
            DonationItem item = DonationItem.builder()
                    .code(randomCodeDonationItemCode(String.valueOf(category.getId())))
                    .name(itemReq.getName())
                    .description(itemReq.getDescription())
                    .conditionGrade(itemReq.getConditionGrade())
                    .status(DonationItemStatus.AT_EVENT)
                    .ecoPointValue(itemReq.getEcoPointValue())
                    .category(category)
                    .donation(donation)
                    .build();

            if (imageFile != null && !imageFile.isEmpty()) {
                handleImageUpload(item, imageFile);
            }
            items.add(item);
        }
        donation.setDonationItems(items);
        Donation savedDonation = donationRepository.save(donation);
        log.info("Save Donation success with Code and ID: {}, {}", savedDonation.getCode(), savedDonation.getId());
        EcoPointTransactionDTO ecoPointTransaction = EcoPointTransactionDTO.builder()
                .userId(request.getUserId())
                .points(donation.getDonationItems().stream().mapToInt(DonationItem::getEcoPointValue).sum())
                .description("Cộng điểm trao đổi của đơn với ID là: " + savedDonation.getId())
                .sourceType(SourceType.DONATION)
                .sourceId(savedDonation.getId())
                .type(EcoPointType.EARNED)
                .build();
        log.info("Sending EcoPointTransactionDTO to stream: {}", ecoPointTransaction);
        boolean ecoPointUpdated = false;

        try {
            Boolean result = rewardServiceFeign.updateEcoPoints(ecoPointTransaction);
            ecoPointUpdated = Boolean.TRUE.equals(result);

            if (!ecoPointUpdated) {
                ecoPointDonationProducer.sendEcoPointDonationMessage(ecoPointTransaction);
                log.warn(
                        "Eco point update failed, queued for retry. donationId={}",
                        savedDonation.getId());
            }
        } catch (Exception e) {
            ecoPointDonationProducer.sendEcoPointDonationMessage(ecoPointTransaction);
            log.error(
                    "Reward service error, eco point queued for retry. donationId={}",
                    savedDonation.getId(),
                    e);
        }

        String notificationMessage;

        if (ecoPointUpdated) {
            notificationMessage =
                    "Bạn đã quyên góp thành công và nhận được "
                            + ecoPointTransaction.getPoints()
                            + " điểm Eco Point.";
        } else {
            notificationMessage =
                    "Bạn đã quyên góp thành công. Hệ thống đang xử lý cộng điểm Eco Point và sẽ cập nhật sớm nhất.";
        }

        notificationProducer.sendNotificationMessage(
                NotificationEvent.builder()
                        .userId(request.getUserId())
                        .title("Quyên góp thành công")
                        .message(notificationMessage)
                        .build());

        return savedDonation.getId();
    }

    @Override
    public List<DonationResponse> getDonationsByEventId(Long eventId) {
        log.info("Get Donations by Event ID: {}", eventId);
        List<Donation> donations = donationRepository.findByEventId(eventId);
        if (!donations.isEmpty()) {
            List<DonationResponse> responseList = new ArrayList<>();
            for (Donation donation : donations) {
                DonationResponse response = DonationResponse.builder()
                        .id(donation.getId())
                        .code(donation.getCode())
                        .totalWeight(donation.getTotalWeight())
                        .totalEcoPoints(donation.getDonationItems().stream().mapToInt(DonationItem::getEcoPointValue).sum())
                        .totalItems(donation.getDonationItems().size())
                        .build();
                responseList.add(response);
            }
            return responseList;
        }
        return List.of();
    }

    @Override
    public List<DonationResponse> getMyDonations() {
        log.info("Get My Donations");
        Long currentUserId = getCurrentUserId();
        log.info("Current User ID: {}", currentUserId);
        List<Donation> donations = donationRepository.findByUserId(currentUserId);
        if (!donations.isEmpty()) {
            List<DonationResponse> responseList = new ArrayList<>();
            for (Donation donation : donations) {
                DonationResponse response = DonationResponse.builder()
                        .id(donation.getId())
                        .code(donation.getCode())
                        .totalWeight(donation.getTotalWeight())
                        .totalEcoPoints(donation.getDonationItems().stream().mapToInt(DonationItem::getEcoPointValue).sum())
                        .totalItems(donation.getDonationItems().size())
                        .build();
                responseList.add(response);
            }
            return responseList;
        }
        return List.of();
    }

    @Override
    public DonationDetailResponse getDonationById(Long donationId) {
        log.info("Get Donation Detail by ID: {}", donationId);
        Donation donation = donationRepository.findById(donationId).orElseThrow(
                () -> new BusinessException(ErrorCode.DONATION_NOT_FOUND));
        Long currentUserId = getCurrentUserId();
        Collection<? extends GrantedAuthority> authorities =
                SecurityContextHolder.getContext().getAuthentication().getAuthorities();

        boolean isPrivileged = authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(role -> Arrays.asList(
                                "ROLE_ADMIN", "ROLE_STAFF", "ROLE_STORE_MANAGER", "ROLE_MANAGER")
                        .contains(role));

        if (!isPrivileged && !donation.getUserId().equals(currentUserId)) {
            throw new BusinessException(ErrorCode.ACCESS_DENIED);
        }

        UserProfileResponse inspectorProfile = null;
        try {
            inspectorProfile = userServiceFeign.getUserInfoById(donation.getInspectedBy());
        } catch (Exception e) {
            log.error("Error fetching inspector profile for user ID {}: {}", donation.getInspectedBy(), e.getMessage());
        }

        return DonationDetailResponse.builder()
                .id(donation.getId())
                .code(donation.getCode())
                .totalWeight(donation.getTotalWeight())
                .totalEcoPoints(donation.getDonationItems().stream().mapToInt(DonationItem::getEcoPointValue).sum())
                .totalItems(donation.getDonationItems().size())
                .inspectedBy(donation.getInspectedBy())
                .inspectedName(inspectorProfile != null ? inspectorProfile.getFullName() : "xxxx")
                .eventId(donation.getEventId())
                .userId(donation.getUserId())
                .donationItems(
                        donation.getDonationItems() != null ?
                                donation.getDonationItems().stream()
                                        .map(item -> DonationItemResponse.builder()
                                                .id(item.getId())
                                                .name(item.getName())
                                                .code(item.getCode())
                                                .categoryId(item.getCategory().getId())
                                                .categoryName(item.getCategory().getName())
                                                .conditionGrade(item.getConditionGrade())
                                                .ecoPoints(item.getEcoPointValue())
                                                .imageUrl(item.getImageUrl())
                                                .status(item.getStatus())
                                                .build())
                                        .collect(Collectors.toList())
                                : Collections.emptyList()
                )
                .build();
    }

    @Override
    @Transactional
    public UpdateDonationItemStatusResponse changeStatusDonationItems(UpdateDonationItemStatusRequest request) {

        List<String> codes = request.getDonationItemCodes();
        DonationItemStatus newStatus = request.getDonationItemStatus();

        log.info("Updating donation items status. Codes: {}, New status: {}", codes, newStatus);

        List<DonationItem> items = donationItemRepository.findAllByCodeIn(codes);

        Set<String> foundCodes = items.stream()
                .map(DonationItem::getCode)
                .collect(Collectors.toSet());

        List<String> notFoundCodes = codes.stream()
                .filter(code -> !foundCodes.contains(code))
                .toList();

        items.forEach(item -> item.setStatus(newStatus));
        donationItemRepository.saveAll(items);

        List<String> updatedCodes = items.stream()
                .map(DonationItem::getCode)
                .toList();

        log.info("Updated {} items. Not found: {}", updatedCodes.size(), notFoundCodes);

        return UpdateDonationItemStatusResponse.builder()
                .updatedCodes(updatedCodes)
                .notFoundCodes(notFoundCodes)
                .build();
    }

    @Override
    public PageResponseDTO<DonationItemDetailResponse> getDonationItems(
            String code,
            String name,
            Long donationId,
            DonationItemStatus status,
            Long eventId,
            Pageable pageable) {

        Specification<DonationItem> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (code != null && !code.isEmpty()) {
                String codePattern = "%" + code.toLowerCase() + "%";
                predicates.add(cb.like(cb.lower(root.get("code")), codePattern));
            }

            if (name != null && !name.isEmpty()) {
                String namePattern = "%" + name.toLowerCase() + "%";
                predicates.add(cb.like(cb.lower(root.get("name")), namePattern));
            }

            if (donationId != null) {
                predicates.add(cb.equal(root.get("donation").get("id"), donationId));
            }

            // Filter by status
            if (status != null) {
                predicates.add(cb.equal(root.get("status"), status));
            }

            // Filter by eventId (join sang Donation)
            if (eventId != null) {
                predicates.add(cb.equal(root.get("donation").get("eventId"), eventId));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };

        Page<DonationItem> page = donationItemRepository.findAll(spec, pageable);

        Page<DonationItemDetailResponse> donationItemPage = page.map(this::mapDonationItemToDetailResponse);

        return PageResponseUtil.toPageResponse(donationItemPage);
    }

    private DonationItemDetailResponse mapDonationItemToDetailResponse(DonationItem item) {
        Long eventId = item.getDonation().getEventId();
        String eventName = "";

        if (eventId != null) {
            if (eventNameCache.containsKey(eventId)) {
                eventName = eventNameCache.get(eventId);
            } else {
                try {
                    EventResponse event = eventServiceFeign.getInfoEventId(eventId);
                    if (event != null) {
                        eventName = event.getName();
                        eventNameCache.put(eventId, eventName);
                    }
                } catch (Exception e) {
                    log.error("Error fetching event name for event ID {}: {}", eventId, e.getMessage());
                }
            }
        }

        return DonationItemDetailResponse.builder()
                .id(item.getId())
                .code(item.getCode())
                .name(item.getName())
                .ecoPoints(item.getEcoPointValue())
                .categoryId(item.getCategory() != null ? item.getCategory().getId() : null)
                .categoryName(item.getCategory() != null ? item.getCategory().getName() : null)
                .conditionGrade(item.getConditionGrade())
                .imageUrl(item.getImageUrl())
                .status(item.getStatus())
                .eventId(eventId)
                .eventName(eventName)
                .build();
    }


    private void validateEcoPointRule(DonationItemCreateRequest itemReq) {
        try {
            String redisKey = ecoPointRedisKey + EcoActionType.DONATION + "_" + itemReq.getCategoryId();
            EcoPointResponse ecoPointRule = cacheService.get(redisKey, EcoPointResponse.class);
            if (ecoPointRule == null) {
                ecoPointRule = rewardServiceFeign.getEcoPoint(EcoPointInfoRequest.builder().ecoActionType(EcoActionType.DONATION).categoryId(itemReq.getCategoryId()).build());
            }

            if (ecoPointRule == null) {
                log.warn("Eco point rule for action type DONATION and category ID {} not found", itemReq.getCategoryId());
            }

            if(ecoPointRule.getIsActive() == null || !ecoPointRule.getIsActive()) {
                log.warn("Eco point rule for action type DONATION and category ID {} is inactive", itemReq.getCategoryId());
                throw new BusinessException(
                        "Quy tắc Eco Point không hoạt động. Vui lòng chọn eco point bạn cảm thấy phù hợp hoặc liên hệ Admin.",
                        ErrorCode.ECO_POINT_RULE_INACTIVE
                );
            }

            if (itemReq.getEcoPointValue() < ecoPointRule.getMinPoints() || itemReq.getEcoPointValue() > ecoPointRule.getMaxPoints()) {
                log.warn("Eco point value {} is out of bounds for category ID {}", itemReq.getEcoPointValue(), itemReq.getCategoryId());
                throw new BusinessException(ErrorCode.ECO_POINT_VALUE_OUT_OF_BOUNDS);
            }
        } catch (Exception e) {
            log.error("Error validating eco point rule: {}", e.getMessage(), e);
            throw new BusinessException(ErrorCode.ECO_POINT_RULE_NOT_FOUND);
        }
    }

    private void handleImageUpload(DonationItem item, MultipartFile file) {
        try {
            if (item.getMediaKey() != null) {
                cloudinaryService.deleteImage(item.getMediaKey());
            }
            Map<String, String> accessKey =
                    this.cloudinaryService.uploadImage(file.getBytes(), localImagePath);
            item.updateImage(
                    cloudinaryService.getImageUrl(accessKey.get("asset_id")), accessKey.get("public_id"));
        } catch (Exception e) {
            log.error("Error while uploading cinema image: {}", e.getMessage(), e);
            throw new BusinessException(ErrorCode.UPLOAD_IMAGE_ERROR);
        }
    }

    private Long getCurrentUserId() {
        return Long.valueOf(
                SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
    }

    private String randomCodeDonationCode() {
        LocalDateTime now = LocalDateTime.now();
        String datePart = now.format(DateTimeFormatter.ofPattern("ddMMyy"));
        String secondPart = String.format("%06d", now.getSecond());
        return "DN_" + datePart + "_" + secondPart;
    }


    private String randomCodeDonationItemCode(String categoryId) {
        LocalDateTime now = LocalDateTime.now();
        String datePart = now.format(DateTimeFormatter.ofPattern("ddMMyy"));
        String secondPart = String.format("%06d", now.getSecond());
        return "DN_PRO_" + categoryId + "_" + datePart + "_" + secondPart;
    }


    @Override
    public List<DonationExportDTO> getExportData(
            Long eventId,
            Long userId,
            DonationItemStatus itemStatus,
            ConditionGrade conditionGrade,
            Long categoryId,
            LocalDateTime startDate,
            LocalDateTime endDate,
            boolean includeItems) {

        Specification<Donation> spec = (root, query, cb) -> {
            List<jakarta.persistence.criteria.Predicate> predicates = new ArrayList<>();

            if (eventId != null) {
                predicates.add(cb.equal(root.get("eventId"), eventId));
            }
            if (userId != null) {
                predicates.add(cb.equal(root.get("userId"), userId));
            }
            if (startDate != null && endDate != null) {
                predicates.add(cb.between(root.get("createdAt"), startDate, endDate));
            }

            return cb.and(predicates.toArray(new jakarta.persistence.criteria.Predicate[0]));
        };

        List<Donation> donations = donationRepository.findAll((Sort) spec);
        List<DonationExportDTO> exportList = new ArrayList<>();
        DateTimeFormatter dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

        for (Donation donation : donations) {
            EventResponse event = null;
            try {
                event = eventServiceFeign.getInfoEventId(donation.getEventId());
            } catch (Exception e) {
                log.error("Error fetching event: {}", donation.getEventId(), e);
            }

            UserProfileResponse inspector = null;
            try {
                inspector = userServiceFeign.getUserInfoById(donation.getInspectedBy());
            } catch (Exception e) {
                log.error("Error fetching inspector: {}", donation.getInspectedBy(), e);
            }

            if (!includeItems || donation.getDonationItems().isEmpty()) {
                exportList.add(DonationExportDTO.builder()
                        .donationId(String.valueOf(donation.getId()))
                        .donationCode(donation.getCode())
                        .userId(String.valueOf(donation.getUserId()))
                        .eventId(String.valueOf(donation.getEventId()))
                        .eventCode(event != null ? event.getCode() : "")
                        .eventName(event != null ? event.getName() : "")
                        .donationNote(donation.getNote() != null ? donation.getNote() : "")
                        .inspectedBy(String.valueOf(donation.getInspectedBy()))
                        .inspectorName(inspector != null ? inspector.getFullName() : "")
                        .donationCreatedAt(donation.getCreatedAt().format(dateFormatter))
                        .build());
            } else {
                boolean isFirstRow = true;
                List<DonationItem> filteredItems = donation.getDonationItems().stream()
                        .filter(item -> itemStatus == null || item.getStatus() == itemStatus)
                        .filter(item -> conditionGrade == null || item.getConditionGrade() == conditionGrade)
                        .filter(item -> categoryId == null ||
                                (item.getCategory() != null && item.getCategory().getId().equals(categoryId)))
                        .collect(Collectors.toList());

                for (DonationItem item : filteredItems) {
                    exportList.add(DonationExportDTO.builder()
                            .donationId(isFirstRow ? String.valueOf(donation.getId()) : "")
                            .donationCode(isFirstRow ? donation.getCode() : "")
                            .userId(isFirstRow ? String.valueOf(donation.getUserId()) : "")
                            .eventId(isFirstRow ? String.valueOf(donation.getEventId()) : "")
                            .eventCode(isFirstRow && event != null ? event.getCode() : "")
                            .eventName(isFirstRow && event != null ? event.getName() : "")
                            .donationNote(isFirstRow && donation.getNote() != null ? donation.getNote() : "")
                            .inspectedBy(isFirstRow ? String.valueOf(donation.getInspectedBy()) : "")
                            .inspectorName(isFirstRow && inspector != null ? inspector.getFullName() : "")
                            .donationCreatedAt(isFirstRow ? donation.getCreatedAt().format(dateFormatter) : "")
                            // Item info - all rows
                            .itemId(String.valueOf(item.getId()))
                            .itemCode(item.getCode())
                            .itemName(item.getName())
                            .itemDescription(item.getDescription() != null ? item.getDescription() : "")
                            .categoryName(item.getCategory() != null ? item.getCategory().getName() : "")
                            .conditionGrade(item.getConditionGrade() != null ? item.getConditionGrade().name() : "")
                            .ecoPointValue(item.getEcoPointValue() != null ? String.valueOf(item.getEcoPointValue()) : "")
                            .itemStatus(item.getStatus().name())
                            .convertProductId(item.getConvertProductId() != null ?
                                    String.valueOf(item.getConvertProductId()) : "")
                            .imageUrl(item.getImageUrl() != null ? item.getImageUrl() : "")
                            .build());
                    isFirstRow = false;
                }
            }
        }

        return exportList;
    }

}
