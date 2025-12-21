package com.greenloop.reward.service.impl;

import com.greenloop.reward.dto.event.EcoPointTransactionDTO;
import com.greenloop.reward.dto.event.NotificationEvent;
import com.greenloop.reward.dto.response.*;
import com.greenloop.reward.entity.EcoPointTransaction;
import com.greenloop.reward.entity.EcoPointUser;
import com.greenloop.reward.enums.EcoPointStatus;
import com.greenloop.reward.enums.EcoPointType;
import com.greenloop.reward.enums.SourceType;
import com.greenloop.reward.repository.EcoPointTransactionRepository;
import com.greenloop.reward.repository.EcoPointUserRepository;
import com.greenloop.reward.service.EcoPointUserService;
import com.greenloop.reward.service.NotificationProducer;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import com.greenloop.reward.service.UserServiceFeign;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class EcoPointUserServiceImpl implements EcoPointUserService {
    private final EcoPointUserRepository ecoPointUserRepository;
    private final EcoPointTransactionRepository ecoPointTransactionRepository;
    private final NotificationProducer notificationProducer;
    private final UserServiceFeign userServiceFeign;

    @Override
    @Transactional
    public boolean updateEcoPointUserBalance(EcoPointTransactionDTO ecoPointTransactionDTO) {
        try {
            var ecoPointUserOpt =
                    ecoPointUserRepository.findByUserId(ecoPointTransactionDTO.getUserId());

            Integer finalPoints;

            if (ecoPointUserOpt.isPresent()) {
                var ecoPointUser = ecoPointUserOpt.get();

                EcoPointTransaction ecoPointTransaction =
                        EcoPointTransaction.builder()
                                .points(ecoPointTransactionDTO.getPoints())
                                .type(ecoPointTransactionDTO.getType())
                                .userId(ecoPointTransactionDTO.getUserId())
                                .sourceId(ecoPointTransactionDTO.getSourceId())
                                .sourceType(ecoPointTransactionDTO.getSourceType())
                                .description(ecoPointTransactionDTO.getDescription())
                                .build();

                ecoPointUser.addEcoPointTransaction(ecoPointTransaction);

                ecoPointUser.setTotalPoints(
                        ecoPointUser.getTotalPoints() + ecoPointTransactionDTO.getPoints());
                ecoPointUser.setLifetimePoints(
                        ecoPointUser.getLifetimePoints() + ecoPointTransactionDTO.getPoints());

                ecoPointUserRepository.save(ecoPointUser);

                finalPoints = ecoPointUser.getTotalPoints();
                log.info("EcoPointUser update success. userId={}", ecoPointUser.getUserId());

            } else {
                EcoPointUser ecoPointUser =
                        EcoPointUser.builder()
                                .userId(ecoPointTransactionDTO.getUserId())
                                .totalPoints(ecoPointTransactionDTO.getPoints())
                                .lifetimePoints(ecoPointTransactionDTO.getPoints())
                                .status(EcoPointStatus.ACTIVE)
                                .build();

                EcoPointTransaction ecoPointTransaction =
                        EcoPointTransaction.builder()
                                .points(ecoPointTransactionDTO.getPoints())
                                .type(ecoPointTransactionDTO.getType())
                                .userId(ecoPointTransactionDTO.getUserId())
                                .sourceId(ecoPointTransactionDTO.getSourceId())
                                .sourceType(ecoPointTransactionDTO.getSourceType())
                                .description(ecoPointTransactionDTO.getDescription())
                                .build();

                ecoPointUser.addEcoPointTransaction(ecoPointTransaction);
                ecoPointUserRepository.save(ecoPointUser);

                finalPoints = ecoPointUser.getTotalPoints();
                log.info("EcoPointUser created and save success. userId={}", ecoPointUser.getUserId());
            }

            try {
                NotificationEvent notificationEvent =
                        buildNotificationEvent(ecoPointTransactionDTO, finalPoints);
                notificationProducer.sendNotificationMessage(notificationEvent);
            } catch (Exception e) {
                log.error(
                        "Failed to send notification for userId={}",
                        ecoPointTransactionDTO.getUserId(),
                        e);
            }

            return true;

        } catch (Exception e) {
            log.error("Update EcoPointUser failed. userId={}",
                    ecoPointTransactionDTO.getUserId(), e);
            return false;
        }
    }



    private NotificationEvent buildNotificationEvent(EcoPointTransactionDTO dto, Integer totalPoints) {

    String sourceText =
        switch (dto.getSourceType()) {
          case DONATION -> "hoạt động trao đổi";
          case ORDER -> "đơn hàng";
          case EVENT -> "sự kiện";
          case ADMIN -> null;
          case VOUCHER_EXCHANGE -> null;
        };

    String title;
    String message;

    switch (dto.getType()) {
      case EARNED -> {
        title = "Điểm vừa được cộng!";
        message =
            String.format(
                "Bạn vừa nhận được +%d điểm từ %s. Tổng điểm hiện tại: %d.",
                dto.getPoints(), sourceText, totalPoints);
      }
      case SPEND -> {
        title = "Bạn vừa sử dụng điểm";
        message =
            String.format(
                "Bạn đã tiêu %d điểm cho %s. Tổng điểm hiện tại: %d.",
                dto.getPoints(), sourceText, totalPoints);
      }
      case ADJUST -> {
        title = "Điểm của bạn đã thay đổi";
        message =
            String.format(
                "Hệ thống đã điều chỉnh %d điểm. Lý do: %s",
                dto.getPoints(),
                dto.getDescription() != null ? dto.getDescription() : "Không có mô tả");
      }
      default -> throw new IllegalStateException("Unsupported eco point type");
    }

    return NotificationEvent.builder()
        .userId(dto.getUserId())
        .title(title)
        .message(message)
        .build();
  }

  @Override
  public EcoPointUserResponse getEcoPointOfUser(Long userId) {
    log.info("getEcoPointOfUser called with userId: {}", userId);
    var ecoPointUserOpt = ecoPointUserRepository.findByUserId(userId);
    if (ecoPointUserOpt.isPresent()) {
      var ecoPointUser = ecoPointUserOpt.get();
      log.info("EcoPointUser found: {}", ecoPointUser);
      List<EcoPointUserTransactionResponse> transactions =
          ecoPointUser.getTransactions().stream()
              .map(
                  tx ->
                      EcoPointUserTransactionResponse.builder()
                          .points(tx.getPoints())
                          .type(tx.getType())
                          .description(tx.getDescription())
                          .sourceType(tx.getSourceType())
                          .sourceId(tx.getSourceId())
                          .createdAt(tx.getCreatedAt())
                          .build())
              .toList();

      return EcoPointUserResponse.builder()
          .userId(ecoPointUser.getUserId())
          .totalPoints(ecoPointUser.getTotalPoints())
          .lifetimePoints(ecoPointUser.getLifetimePoints())
          .status(ecoPointUser.getStatus())
          .transactions(transactions)
          .build();
    }
    log.info("EcoPointUser not found for userId: {}", userId);
    EcoPointUser ecoPointUser =
        EcoPointUser.builder()
            .userId(userId)
            .totalPoints(0)
            .lifetimePoints(0)
            .status(EcoPointStatus.ACTIVE)
            .build();
    ecoPointUserRepository.save(ecoPointUser);
    log.info("EcoPointUser created with zero balance for userId: {}", userId);
    return EcoPointUserResponse.builder()
        .userId(ecoPointUser.getUserId())
        .totalPoints(ecoPointUser.getTotalPoints())
        .lifetimePoints(ecoPointUser.getLifetimePoints())
        .status(ecoPointUser.getStatus())
        .transactions(List.of())
        .build();
  }

  @Override
  public EcoPointLeaderboardResponse getEcoPointUserDTOByUser() {
    Long userId;
    try {
      userId = getCurrentUserId();
    } catch (Exception e) {
      userId = null;
    }

    List<EcoPointUserDTO> topUsers =
        ecoPointUserRepository.findTopLifetimeUsers().stream()
            .map(
                row -> {
                  Long id = ((Number) row[0]).longValue();
                  Long lifetimePoints = ((Number) row[2]).longValue();

                  UserProfileResponse userInfo;
                  try {
                    userInfo = userServiceFeign.getUserInfoById(id);
                  } catch (Exception e) {
                    userInfo = null;
                  }
                  String name = userInfo != null ? userInfo.getFullName() : "Unknown";

                  return EcoPointUserDTO.builder()
                      .userId(id)
                      .name(name)
                      .lifetimePoints(lifetimePoints)
                      .build();
                })
            .collect(Collectors.toList());

    if (userId != null) {
      Optional<EcoPointUser> currentUserOpt = ecoPointUserRepository.findByUserId(userId);

      if (currentUserOpt.isPresent()) {
        EcoPointUser currentUser = currentUserOpt.get();

        Long higherCount = ecoPointUserRepository.countUsersWithMoreLifetimePoints(userId);
        int currentRank = higherCount.intValue() + 1;

        return EcoPointLeaderboardResponse.builder()
            .currentUserId(userId)
            .currentUserRank(currentRank)
            .currentUserPoints(currentUser.getTotalPoints())
            .topUsers(topUsers)
            .build();
      }
    }

    return EcoPointLeaderboardResponse.builder().topUsers(topUsers).build();
  }

  @Override
  public void addEcoPointsForOfflineOrder(
      Long customerId, Integer points, String orderId, String orderCode) {
    EcoPointTransactionDTO transactionDTO =
        EcoPointTransactionDTO.builder()
            .userId(customerId)
            .points(points)
            .type(EcoPointType.EARNED)
            .sourceType(SourceType.ORDER)
            .sourceId((long) Math.abs(orderId.hashCode()))
            .description("Mua hàng offline - " + orderCode)
            .build();

    updateEcoPointUserBalance(transactionDTO);
    log.info(
        "Added {} eco points for customer {} from offline order {}", points, customerId, orderCode);
  }

  @Override
  public void addEcoPointsForOnlineOrder(
      Long customerId, Integer points, String orderId, String orderCode) {

    EcoPointTransactionDTO transactionDTO =
        EcoPointTransactionDTO.builder()
            .userId(customerId)
            .points(points)
            .type(EcoPointType.EARNED)
            .sourceType(SourceType.ORDER)
            .sourceId((long) Math.abs(orderId.hashCode()))
            .description("Hoàn thành đơn hàng online - " + orderCode)
            .build();

    updateEcoPointUserBalance(transactionDTO);

    log.info(
        "Added {} eco points for customer {} from online order {}", points, customerId, orderCode);
  }

  private Long getCurrentUserId() {
    return Long.valueOf(
        SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
  }
}
