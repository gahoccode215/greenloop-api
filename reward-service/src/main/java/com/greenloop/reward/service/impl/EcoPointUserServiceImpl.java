package com.greenloop.reward.service.impl;

import com.greenloop.reward.dto.event.EcoPointTransactionDTO;
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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class EcoPointUserServiceImpl implements EcoPointUserService {
    private final EcoPointUserRepository ecoPointUserRepository;
    private final EcoPointTransactionRepository ecoPointTransactionRepository;

    @Override
    public void updateEcoPointUserBalance(EcoPointTransactionDTO ecoPointTransactionDTO) {
        var ecoPointUserOpt = ecoPointUserRepository.findByUserId(ecoPointTransactionDTO.getUserId());
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
            log.info("EcoPointUser created and save success.");
        }
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
        List<EcoPointUserDTO> topUsers = ecoPointUserRepository.findTopLifetimeUsers().stream()
                .map(row -> EcoPointUserDTO.builder()
                        .userId((Long) row[0])
                        .lifetimePoints(((Number) row[2]).longValue())
                        .build())
                .collect(Collectors.toList());

        Long higherCount = ecoPointUserRepository.countUsersWithMoreLifetimePoints(userId);
        int currentRank = higherCount.intValue() + 1;

        EcoPointUser currentUser = ecoPointUserRepository.findByUserId(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return EcoPointLeaderboardResponse.builder()
                .currentUserId(userId)
                .currentUserRank(currentRank)
                .currentUserPoints(currentUser.getTotalPoints())
                .topUsers(topUsers)
                .build();
    }

    @Override
    public void addEcoPointsForOfflineOrder(Long customerId, Integer points, String orderId, String orderCode) {
        EcoPointTransactionDTO transactionDTO = EcoPointTransactionDTO.builder()
                .userId(customerId)
                .points(points)
                .type(EcoPointType.EARNED)
                .sourceType(SourceType.ORDER)
                .sourceId((long) Math.abs(orderId.hashCode()))
                .description("Mua hàng offline - " + orderCode)
                .build();

        updateEcoPointUserBalance(transactionDTO);
        log.info("Added {} eco points for customer {} from offline order {}",
                points, customerId, orderCode);
    }




    private Long getCurrentUserId() {
        return Long.valueOf(
                SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
    }


}
