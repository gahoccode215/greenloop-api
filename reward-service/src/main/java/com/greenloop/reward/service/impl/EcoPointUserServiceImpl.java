package com.greenloop.reward.service.impl;

import com.greenloop.reward.dto.event.EcoPointTransactionDTO;
import com.greenloop.reward.dto.event.NotificationEvent;
import com.greenloop.reward.dto.response.EcoPointLeaderboardResponse;
import com.greenloop.reward.dto.response.EcoPointUserDTO;
import com.greenloop.reward.dto.response.EcoPointUserResponse;
import com.greenloop.reward.dto.response.EcoPointUserTransactionResponse;
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
import java.util.stream.Collectors;
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

    @Override
    public void updateEcoPointUserBalance(EcoPointTransactionDTO ecoPointTransactionDTO) {
        var ecoPointUserOpt = ecoPointUserRepository.findByUserId(ecoPointTransactionDTO.getUserId());
        Integer finalPoints;
        if (ecoPointUserOpt.isPresent()) {
            EcoPointTransaction ecoPointTransaction =
                    EcoPointTransaction.builder()
                            .ecoPointUser(ecoPointUserOpt.get())
                            .points(ecoPointTransactionDTO.getPoints())
                            .type(ecoPointTransactionDTO.getType())
                            .points(ecoPointTransactionDTO.getPoints())
                            .userId(ecoPointTransactionDTO.getUserId())
                            .sourceId(ecoPointTransactionDTO.getSourceId())
                            .sourceType(ecoPointTransactionDTO.getSourceType())
                            .description(ecoPointTransactionDTO.getDescription())
                            .build();
            ecoPointTransactionRepository.save(ecoPointTransaction);
            var ecoPointUser = ecoPointUserOpt.get();
            ecoPointUser.setTotalPoints(
                    ecoPointUser.getTotalPoints() + ecoPointTransactionDTO.getPoints());
            ecoPointUser.setLifetimePoints(
                    ecoPointUser.getLifetimePoints() + ecoPointTransactionDTO.getPoints());
            ecoPointUserRepository.save(ecoPointUser);
            log.info("EcoPointUser save success.");
            finalPoints = ecoPointUser.getTotalPoints();
        } else {
            EcoPointUser ecoPointUser =
                    EcoPointUser.builder()
                            .userId(ecoPointTransactionDTO.getUserId())
                            .totalPoints(ecoPointTransactionDTO.getPoints())
                            .lifetimePoints(ecoPointTransactionDTO.getPoints())
                            .status(EcoPointStatus.ACTIVE)
                            .build();
            ecoPointUser.addEcoPointTransaction(
                    EcoPointTransaction.builder()
                            .ecoPointUser(ecoPointUser)
                            .points(ecoPointTransactionDTO.getPoints())
                            .type(ecoPointTransactionDTO.getType())
                            .userId(ecoPointTransactionDTO.getUserId())
                            .sourceId(ecoPointTransactionDTO.getSourceId())
                            .sourceType(ecoPointTransactionDTO.getSourceType())
                            .description(ecoPointTransactionDTO.getDescription())
                            .build());
            ecoPointUserRepository.save(ecoPointUser);
            finalPoints = ecoPointUser.getTotalPoints();
            log.info("EcoPointUser created and save success.");
        }
        NotificationEvent notificationEvent = buildNotificationEvent(ecoPointTransactionDTO, finalPoints);
        notificationProducer.sendNotificationMessage(notificationEvent);
    }

    private NotificationEvent buildNotificationEvent(EcoPointTransactionDTO dto, Integer totalPoints) {

        String sourceText = switch (dto.getSourceType()) {
            case DONATION -> "hoạt động trao đổi";
            case ORDER    -> "đơn hàng";
            case EVENT    -> "sự kiện";
            case ADMIN -> null;
            case VOUCHER_EXCHANGE -> null;
        };

        String title;
        String message;

        switch (dto.getType()) {
            case EARNED -> {
                title = "Điểm vừa được cộng!";
                message = String.format(
                        "Bạn vừa nhận được +%d điểm từ %s. Tổng điểm hiện tại: %d.",
                        dto.getPoints(), sourceText, totalPoints
                );
            }
            case SPEND -> {
                title = "Bạn vừa sử dụng điểm";
                message = String.format(
                        "Bạn đã tiêu %d điểm cho %s. Tổng điểm hiện tại: %d.",
                        dto.getPoints(), sourceText, totalPoints
                );
            }
            case ADJUST -> {
                title = "Điểm của bạn đã thay đổi";
                message = String.format(
                        "Hệ thống đã điều chỉnh %d điểm. Lý do: %s",
                        dto.getPoints(),
                        dto.getDescription() != null ? dto.getDescription() : "Không có mô tả"
                );
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
    Long userId = getCurrentUserId();
    List<EcoPointUserDTO> topUsers =
        ecoPointUserRepository.findTopLifetimeUsers().stream()
            .map(
                row ->
                    EcoPointUserDTO.builder()
                        .userId((Long) row[0])
                        .lifetimePoints(((Number) row[2]).longValue())
                        .build())
            .collect(Collectors.toList());

    Long higherCount = ecoPointUserRepository.countUsersWithMoreLifetimePoints(userId);
    int currentRank = higherCount.intValue() + 1;

    EcoPointUser currentUser =
        ecoPointUserRepository
            .findByUserId(userId)
            .orElseThrow(() -> new RuntimeException("User not found"));

    return EcoPointLeaderboardResponse.builder()
        .currentUserId(userId)
        .currentUserRank(currentRank)
        .currentUserPoints(currentUser.getTotalPoints())
        .topUsers(topUsers)
        .build();
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

  private Long getCurrentUserId() {
    return Long.valueOf(
        SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
  }
}
