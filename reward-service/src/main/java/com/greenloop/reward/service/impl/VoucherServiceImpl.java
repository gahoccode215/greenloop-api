package com.greenloop.reward.service.impl;

import com.greenloop.reward.dto.request.CreateVoucherCampaignRequest;
import com.greenloop.reward.dto.request.CreateVoucherRequest;
import com.greenloop.reward.dto.response.UserVoucherResponse;
import com.greenloop.reward.dto.response.VoucherCampaignResponse;
import com.greenloop.reward.dto.response.VoucherResponse;
import com.greenloop.reward.entity.*;
import com.greenloop.reward.enums.*;
import com.greenloop.reward.exception.BusinessException;
import com.greenloop.reward.repository.*;
import com.greenloop.reward.service.VoucherService;
import jakarta.transaction.Transactional;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Slf4j
@RequiredArgsConstructor
@Service
public class VoucherServiceImpl implements VoucherService {

  private final VoucherCampaignRepository voucherCampaignRepository;
  private final VoucherRepository voucherRepository;
  private final EcoPointUserRepository ecoPointUserRepository;
  private final EcoPointTransactionRepository ecoPointTransactionRepository;
  private final VoucherUserRepository voucherUserRepository;

  @Override
  public Long createVoucherCampaign(CreateVoucherCampaignRequest request) {
    Long userId = getCurrentUserId();
    validateTimeFrame(request);
    log.info("Creating voucher campaign for user ID: {}", userId);
    VoucherCampaign voucherCampaign =
        VoucherCampaign.builder()
            .name(request.getCampaignName())
            .description(request.getDescription())
            .startDate(request.getStartDate())
            .endDate(request.getEndDate())
            .build();

    if (request.getVouchers() != null && !request.getVouchers().isEmpty()) {
      request
          .getVouchers()
          .forEach(
              voucherRequest -> {
                Voucher voucher =
                    Voucher.builder()
                        .code(generateVoucherCode())
                        .name(voucherRequest.getName())
                        .description(voucherRequest.getDescription())
                        .type(voucherRequest.getVoucherType())
                        .value(voucherRequest.getValue())
                        .quantity(voucherRequest.getQuantity())
                        .pointToRedeem(voucherRequest.getPointToRedeem())
                        .expiryDate(voucherRequest.getExpiryDate())
                        .minOrderValue(voucherRequest.getMinOrderValue())
                        .maxDiscount(voucherRequest.getMaxDiscount())
                        .build();
                voucherCampaign.addVoucher(voucher);
              });
    }
    VoucherCampaign newCampaign = voucherCampaignRepository.save(voucherCampaign);
    log.info("Voucher campaign created with ID: {}", voucherCampaign.getId());
    return newCampaign.getId();
  }

  @Override
  public Long createVoucher(CreateVoucherRequest request) {
    Long currentUserId = getCurrentUserId();
    log.info("Creating voucher for user ID: {}", currentUserId);
    if (request.getCampaignId() == null) {
      throw new BusinessException(ErrorCode.VOUCHER_CAMPAIGN_ID_REQUIRED);
    }

    VoucherCampaign voucherCampaign =
        voucherCampaignRepository
            .findById(request.getCampaignId())
            .orElseThrow(() -> new BusinessException(ErrorCode.VOUCHER_CAMPAIGN_NOT_FOUND));
    Voucher voucher =
        Voucher.builder()
            .code(generateVoucherCode())
            .name(request.getName())
            .description(request.getDescription())
            .type(request.getVoucherType())
            .value(request.getValue())
            .quantity(request.getQuantity())
            .pointToRedeem(request.getPointToRedeem())
            .status(VoucherStatus.ACTIVE)
            .expiryDate(request.getExpiryDate())
            .minOrderValue(request.getMinOrderValue())
            .maxDiscount(request.getMaxDiscount())
            .campaign(voucherCampaign)
            .build();
    voucher = voucherRepository.save(voucher);
    log.info("Voucher created with code: {}", voucher.getCode());
    return voucher.getId();
  }

  @Override
  public void updateVoucherCampaign(CreateVoucherCampaignRequest request, Long campaignId) {
    VoucherCampaign voucherCampaign =
        voucherCampaignRepository
            .findById(campaignId)
            .orElseThrow(() -> new BusinessException(ErrorCode.VOUCHER_CAMPAIGN_NOT_FOUND));
    validateTimeFrame(request);
    voucherCampaign.setName(request.getCampaignName());
    voucherCampaign.setDescription(request.getDescription());
    voucherCampaign.setStartDate(request.getStartDate());
    voucherCampaign.setEndDate(request.getEndDate());
    voucherCampaignRepository.save(voucherCampaign);
    log.info("Voucher campaign with ID: {} updated successfully", campaignId);
  }

  @Override
  public void updateVoucher(CreateVoucherRequest request, Long voucherId) {

    Voucher voucher =
        voucherRepository
            .findById(voucherId)
            .orElseThrow(() -> new BusinessException(ErrorCode.VOUCHER_NOT_FOUND));
    voucher.setName(request.getName());
    voucher.setDescription(request.getDescription());
    voucher.setType(request.getVoucherType());
    voucher.setValue(request.getValue());
    voucher.setMinOrderValue(request.getMinOrderValue());
    voucher.setMaxDiscount(request.getMaxDiscount());
    voucher.setExpiryDate(request.getExpiryDate());
    voucher.setQuantity(request.getQuantity());
    voucher.setPointToRedeem(request.getPointToRedeem());

    voucher.updatedBy(getCurrentUserId());
    voucherRepository.save(voucher);
    log.info("Voucher with ID: {} updated successfully", voucherId);
  }

  @Override
  public void changeVoucherStatus(Long voucherId, VoucherStatus status) {
    Voucher voucher =
        voucherRepository
            .findById(voucherId)
            .orElseThrow(() -> new BusinessException(ErrorCode.VOUCHER_NOT_FOUND));
    voucher.setStatus(status);
    voucher.updatedBy(getCurrentUserId());
    voucherRepository.save(voucher);
    log.info("Voucher with ID: {} status changed to {}", voucherId, status);
  }

  @Override
  public void toggleVoucherStatus(Long voucherId) {
    Voucher voucher =
        voucherRepository
            .findById(voucherId)
            .orElseThrow(() -> new BusinessException(ErrorCode.VOUCHER_NOT_FOUND));
    voucher.setActive(!voucher.isActive());
    voucher.updatedBy(getCurrentUserId());
    voucherRepository.save(voucher);
    log.info("Voucher with ID: {} status toggled successfully", voucherId);
  }

  @Override
  public Page<VoucherCampaignResponse> getVoucherCampaignsForCustomer(
      String name, LocalDateTime from, LocalDateTime to, int page, int size) {

    Pageable pageable = PageRequest.of(page, size);

    Specification<VoucherCampaign> spec =
        (root, query, cb) -> {
          var predicates = cb.conjunction();

          if (name != null && !name.isEmpty()) {
            String searchPattern = "%" + name.toLowerCase() + "%";
            predicates = cb.and(predicates, cb.like(cb.lower(root.get("name")), searchPattern));
          }

          if (from != null) {
            predicates = cb.and(predicates, cb.greaterThanOrEqualTo(root.get("startDate"), from));
          }

          if (to != null) {
            predicates = cb.and(predicates, cb.lessThanOrEqualTo(root.get("endDate"), to));
          }

          predicates =
              cb.and(
                  predicates,
                  cb.isTrue(root.get("isActive")),
                  cb.greaterThanOrEqualTo(root.get("endDate"), LocalDateTime.now()));

          return predicates;
        };

    Page<VoucherCampaign> campaigns = voucherCampaignRepository.findAll(spec, pageable);

    return campaigns.map(
        campaign ->
            VoucherCampaignResponse.builder()
                .campaignId(campaign.getId())
                .campaignName(campaign.getName())
                .campaignDescription(campaign.getDescription())
                .startDate(campaign.getStartDate())
                .endDate(campaign.getEndDate())
                .isActive(campaign.isActive())
                .build());
  }

  @Override
  public Page<VoucherCampaignResponse> getVoucherCampaignsForAdmin(
      String name, LocalDateTime from, LocalDateTime to, int page, int size) {

    Pageable pageable = PageRequest.of(page, size);

    Specification<VoucherCampaign> spec =
        (root, query, cb) -> {
          var predicates = cb.conjunction();

          if (name != null && !name.isEmpty()) {
            String searchPattern = "%" + name.toLowerCase() + "%";
            predicates = cb.and(predicates, cb.like(cb.lower(root.get("name")), searchPattern));
          }

          if (from != null) {
            predicates = cb.and(predicates, cb.greaterThanOrEqualTo(root.get("startDate"), from));
          }

          if (to != null) {
            predicates = cb.and(predicates, cb.lessThanOrEqualTo(root.get("endDate"), to));
          }

          predicates = cb.and(predicates, cb.isTrue(root.get("isActive")));

          return predicates;
        };

    Page<VoucherCampaign> campaigns = voucherCampaignRepository.findAll(spec, pageable);

    return campaigns.map(
        campaign ->
            VoucherCampaignResponse.builder()
                .campaignId(campaign.getId())
                .campaignName(campaign.getName())
                .campaignDescription(campaign.getDescription())
                .startDate(campaign.getStartDate())
                .endDate(campaign.getEndDate())
                .isActive(campaign.isActive())
                .build());
  }

  @Override
  public Page<VoucherResponse> getVouchersForAdmin(
      Long campaignId,
      String code,
      String name,
      VoucherType voucherType,
      VoucherStatus status,
      BigDecimal minOrderValue,
      BigDecimal maxDiscount,
      Boolean active,
      int page,
      int size) {

    Pageable pageable = PageRequest.of(page, size);

    Specification<Voucher> spec =
        (root, query, cb) -> {
          var predicates = cb.conjunction();

          if (campaignId != null) {
            predicates = cb.and(predicates, cb.equal(root.get("campaign").get("id"), campaignId));
          }

          if (code != null && !code.isEmpty()) {
            String searchPattern = "%" + code.toLowerCase() + "%";
            predicates = cb.and(predicates, cb.like(cb.lower(root.get("code")), searchPattern));
          }

          if (name != null && !name.isEmpty()) {
            String searchPattern = "%" + name.toLowerCase() + "%";
            predicates = cb.and(predicates, cb.like(cb.lower(root.get("name")), searchPattern));
          }

          if (voucherType != null) {
            predicates = cb.and(predicates, cb.equal(root.get("type"), voucherType));
          }

          if (status != null) {
            predicates = cb.and(predicates, cb.equal(root.get("status"), status));
          }

          if (minOrderValue != null) {
            predicates =
                cb.and(
                    predicates, cb.greaterThanOrEqualTo(root.get("minOrderValue"), minOrderValue));
          }

          if (maxDiscount != null) {
            predicates =
                cb.and(predicates, cb.lessThanOrEqualTo(root.get("maxDiscount"), maxDiscount));
          }

          if (active != null) {
            predicates = cb.and(predicates, cb.equal(root.get("isActive"), active));
          }

          return predicates;
        };

    Page<Voucher> vouchers = voucherRepository.findAll(spec, pageable);

    return vouchers.map(
        voucher ->
            VoucherResponse.builder()
                .voucherId(voucher.getId())
                .campaignId(voucher.getCampaign() != null ? voucher.getCampaign().getId() : null)
                .code(voucher.getCode())
                .description(voucher.getDescription())
                .voucherStatus(voucher.getStatus())
                .voucherType(voucher.getType())
                .value(voucher.getValue())
                .minOrderValue(voucher.getMinOrderValue())
                .maxDiscount(voucher.getMaxDiscount())
                .expiryDate(voucher.getExpiryDate())
                .quantity(voucher.getQuantity())
                .pointToRedeem(voucher.getPointToRedeem())
                .availableQuantity(voucher.getAvailableQuantity())
                .active(voucher.isActive())
                .build());
  }

  @Override
  public Page<VoucherResponse> getVouchersForCustomer(
      Long campaignId,
      String code,
      String name,
      VoucherType voucherType,
      VoucherStatus status,
      BigDecimal minOrderValue,
      BigDecimal maxDiscount,
      int page,
      int size) {

    Pageable pageable = PageRequest.of(page, size);

    Specification<Voucher> spec =
        (root, query, cb) -> {
          var predicates = cb.conjunction();

          if (campaignId != null) {
            predicates = cb.and(predicates, cb.equal(root.get("campaign").get("id"), campaignId));
          }

          if (code != null && !code.isEmpty()) {
            String searchPattern = "%" + code.toLowerCase() + "%";
            predicates = cb.and(predicates, cb.like(cb.lower(root.get("code")), searchPattern));
          }

          if (name != null && !name.isEmpty()) {
            String searchPattern = "%" + name.toLowerCase() + "%";
            predicates = cb.and(predicates, cb.like(cb.lower(root.get("name")), searchPattern));
          }

          if (voucherType != null) {
            predicates = cb.and(predicates, cb.equal(root.get("type"), voucherType));
          }

          if (status != null) {
            predicates = cb.and(predicates, cb.equal(root.get("status"), status));
          }

          if (minOrderValue != null) {
            predicates =
                cb.and(
                    predicates, cb.greaterThanOrEqualTo(root.get("minOrderValue"), minOrderValue));
          }

          if (maxDiscount != null) {
            predicates =
                cb.and(predicates, cb.lessThanOrEqualTo(root.get("maxDiscount"), maxDiscount));
          }

          predicates =
              cb.and(
                  predicates,
                  cb.isTrue(root.get("isActive")),
                  cb.greaterThanOrEqualTo(root.get("expiryDate"), LocalDateTime.now()));

          return predicates;
        };

    Page<Voucher> vouchers = voucherRepository.findAll(spec, pageable);

    return vouchers.map(
        voucher ->
            VoucherResponse.builder()
                .voucherId(voucher.getId())
                .campaignId(voucher.getCampaign() != null ? voucher.getCampaign().getId() : null)
                .code(voucher.getCode())
                .description(voucher.getDescription())
                .voucherStatus(voucher.getStatus())
                .voucherType(voucher.getType())
                .value(voucher.getValue())
                .minOrderValue(voucher.getMinOrderValue())
                .maxDiscount(voucher.getMaxDiscount())
                .expiryDate(voucher.getExpiryDate())
                .quantity(voucher.getQuantity())
                .pointToRedeem(voucher.getPointToRedeem())
                .availableQuantity(voucher.getAvailableQuantity())
                .active(voucher.isActive())
                .build());
  }

  @Override
  @Transactional
  public Long redeemVoucher(Long voucherId) {
    Long userId = getCurrentUserId();
    log.info("User ID: {} is redeeming voucher ID: {}", userId, voucherId);

    Voucher voucher =
        voucherRepository
            .findById(voucherId)
            .orElseThrow(() -> new BusinessException(ErrorCode.VOUCHER_NOT_FOUND));

    EcoPointUser ecoPointUser =
        ecoPointUserRepository
            .findByUserId(userId)
            .orElseThrow(() -> new BusinessException(ErrorCode.ECO_POINT_USER_NOT_FOUND));

    validateCanRedeem(voucher, ecoPointUser);

    ecoPointUser.setTotalPoints(ecoPointUser.getTotalPoints() - voucher.getPointToRedeem());

    EcoPointTransaction transaction =
        EcoPointTransaction.builder()
            .ecoPointUser(ecoPointUser)
            .userId(userId)
            .points(-voucher.getPointToRedeem())
            .sourceType(SourceType.VOUCHER_EXCHANGE)
            .sourceId(voucherId)
            .description("Redeemed voucher: " + voucher.getCode())
            .build();

    Optional<VoucherUser> existingRecord =
        voucherUserRepository.findByVoucherIdAndUserId(voucherId, userId);

    VoucherUser voucherUser;

    if (existingRecord.isPresent()) {
      voucherUser = existingRecord.get();
      int newQty = voucherUser.getQuantity() + 1;
      voucherUser.setQuantity(newQty);
      log.info("Voucher user exists. Increasing quantity to {}", newQty);

    } else {
      voucherUser =
          VoucherUser.builder()
              .voucher(voucher)
              .assignedAt(LocalDateTime.now())
              .userId(userId)
              .quantity(1)
              .status(VoucherUserStatus.AVAILABLE)
              .build();
      log.info("Creating new voucher_user record for user {}", userId);
    }

    ecoPointUserRepository.save(ecoPointUser);
    ecoPointTransactionRepository.save(transaction);
    VoucherUser saved = voucherUserRepository.save(voucherUser);

    log.info("Voucher ID: {} redeemed successfully by user ID: {}", voucherId, userId);
    return saved.getId();
  }

  @Override
  public List<UserVoucherResponse> myVouchers() {
    Long userId = getCurrentUserId();
    log.info("Fetching vouchers for user ID: {}", userId);
    List<VoucherUser> voucherUsers =
        voucherUserRepository.findAllByUserId(userId).stream()
            .sorted(
                Comparator.comparing(
                    vu -> vu.getVoucher().getExpiryDate(),
                    Comparator.nullsLast(Comparator.naturalOrder())))
            .toList();

    return voucherUsers.stream()
        .map(
            vu -> {
              Voucher voucher = vu.getVoucher();

              return UserVoucherResponse.builder()
                  .voucherUserId(vu.getId())
                  .voucherId(voucher.getId())
                  .voucherCode(voucher.getCode())
                  .voucherName(voucher.getName())
                  .assignedAt(vu.getAssignedAt())
                  .status(vu.getStatus())
                  .quantity(vu.getQuantity())
                  .maxDiscount(vu.getVoucher().getMaxDiscount())
                  .value(voucher.getValue())
                  .minOrderValue(voucher.getMinOrderValue())
                  .expiryDate(voucher.getExpiryDate())
                  .active(voucher.isActive())
                  .voucherUserStatus(vu.getStatus())
                  .build();
            })
        .toList();
  }

  public void validateCanRedeem(Voucher voucher, EcoPointUser ecoPointUser) {

    if (voucher.getStatus() != VoucherStatus.ACTIVE) {
      throw new BusinessException(ErrorCode.VOUCHER_IS_NOT_ACTIVE);
    }

    if (voucher.getExpiryDate() != null && LocalDateTime.now().isAfter(voucher.getExpiryDate())) {
      throw new BusinessException(ErrorCode.VOUCHER_EXPIRED);
    }

    if (ecoPointUser.getTotalPoints() < voucher.getPointToRedeem()) {
      throw new BusinessException(ErrorCode.INSUFFICIENT_ECO_POINTS);
    }

    if (voucher.getQuantity() != null && voucher.getQuantity() <= 0) {
      throw new BusinessException(ErrorCode.VOUCHER_OUT_OF_STOCK);
    }
  }

  private void validateTimeFrame(CreateVoucherCampaignRequest request) {
    if (request.getEndDate().isBefore(request.getStartDate())) {
      throw new BusinessException(ErrorCode.INVALID_TIME_FRAME);
    }
  }

  private Long getCurrentUserId() {
    return Long.valueOf(
        SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
  }

  private String generateVoucherCode() {
    LocalDateTime now = LocalDateTime.now();
    String datePart = now.format(DateTimeFormatter.ofPattern("ddMMyy"));
    String secondPart = String.format("%06d", now.getSecond());
    return "VCR_" + datePart + secondPart;
  }
}
