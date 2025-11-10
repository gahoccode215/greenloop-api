package com.greenloop.product.service.impl;

import com.greenloop.product.dto.request.DonationCreateRequest;
import com.greenloop.product.dto.request.DonationItemCreateRequest;
import com.greenloop.product.dto.request.EcoPointInfoRequest;
import com.greenloop.product.dto.response.EcoPointResponse;
import com.greenloop.product.entity.Category;
import com.greenloop.product.entity.Donation;
import com.greenloop.product.entity.DonationItem;
import com.greenloop.product.enums.EcoActionType;
import com.greenloop.product.enums.ErrorCode;
import com.greenloop.product.exception.BusinessException;
import com.greenloop.product.repository.CategoryRepository;
import com.greenloop.product.repository.DonationRepository;
import com.greenloop.product.service.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class DonationServiceImpl implements DonationService {

    private final CloudinaryService cloudinaryService;
    private final RewardServiceFeign rewardServiceFeign;
    private final EventServiceFeign eventServiceFeign;
    private final CacheService cacheService;
    private final CategoryRepository categoryRepository;
    private final DonationRepository donationRepository;
    private final String localImagePath = "GreenLoop/Donations";
    private final String ecoPointRedisKey = "eco_point_rule_";

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
                    .name(itemReq.getName())
                    .description(itemReq.getDescription())
                    .conditionGrade(itemReq.getConditionGrade())
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
        return savedDonation.getId();
    }

    private void validateEcoPointRule(DonationItemCreateRequest itemReq) {
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

}
