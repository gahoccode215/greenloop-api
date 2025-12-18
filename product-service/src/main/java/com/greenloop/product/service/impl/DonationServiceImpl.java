package com.greenloop.product.service.impl;

import com.greenloop.product.dto.event.EcoPointTransactionDTO;
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
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
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

    private final String donationEcoPointBindingName = "ecoPointDonation-out-0";

    @Override
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
                .description("Eco points for donation ID: " + savedDonation.getId())
                .sourceType(SourceType.DONATION)
                .sourceId(savedDonation.getId())
                .type(EcoPointType.EARNED)
                .build();
        log.info("Sending EcoPointTransactionDTO to stream: {}", ecoPointTransaction);
        ecoPointDonationProducer.sendEcoPointDonationMessage(ecoPointTransaction);
        try {
            Boolean result = rewardServiceFeign.updateEcoPoints(ecoPointTransaction);
            if(!result) {
                ecoPointDonationProducer.sendEcoPointDonationMessage(ecoPointTransaction);
            }
        }
        catch (Exception e) {
            log.error("Error sending EcoPointTransactionDTO to reward service: {}", e.getMessage(), e);
            ecoPointDonationProducer.sendEcoPointDonationMessage(ecoPointTransaction);
        }
//        log.info("Sending EcoPointTransactionDTO to stream: {}", ecoPointTransaction);
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

}
