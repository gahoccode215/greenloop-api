package com.greenloop.reward.service.impl;

import com.greenloop.reward.dto.response.EcoPointStatisticsResponse;
import com.greenloop.reward.dto.response.VoucherStatisticsResponse;
import com.greenloop.reward.enums.*;
import com.greenloop.reward.repository.*;
import com.greenloop.reward.service.DashboardService;
import java.math.BigDecimal;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class DashboardServiceImpl implements DashboardService {

  private final EcoPointUserRepository ecoPointUserRepository;
  private final EcoPointTransactionRepository ecoPointTransactionRepository;
  private final VoucherRepository voucherRepository;
  private final VoucherCampaignRepository voucherCampaignRepository;
  private final VoucherUserRepository voucherUserRepository;
  private final VoucherRedemptionRepository voucherRedemptionRepository;

  @Override
  public EcoPointStatisticsResponse getEcoPointStatistics() {
    Long totalUsers = ecoPointUserRepository.count();
    Map<EcoPointStatus, Long> usersByStatus =
        Arrays.stream(EcoPointStatus.values())
            .collect(
                Collectors.toMap(
                    status -> status, status -> ecoPointUserRepository.countByStatus(status)));

    List<EcoPointStatisticsResponse.TopUserPoints> topUsers =
        ecoPointUserRepository.findTopUsers().stream()
            .map(
                row ->
                    EcoPointStatisticsResponse.TopUserPoints.builder()
                        .userId((Long) row[0])
                        .totalPoints((Integer) row[1])
                        .lifetimePoints((Integer) row[2])
                        .build())
            .collect(Collectors.toList());

    Long totalTransactions = ecoPointTransactionRepository.count();
    Map<EcoPointType, Long> transactionsByType =
        Arrays.stream(EcoPointType.values())
            .collect(
                Collectors.toMap(
                    type -> type, type -> ecoPointTransactionRepository.countByType(type)));

    Map<SourceType, Long> transactionsBySource =
        Arrays.stream(SourceType.values())
            .collect(
                Collectors.toMap(
                    src -> src, src -> ecoPointTransactionRepository.countBySourceType(src)));

    List<EcoPointStatisticsResponse.TransactionTrend> trend =
        ecoPointTransactionRepository.transactionTrend().stream()
            .map(
                row ->
                    EcoPointStatisticsResponse.TransactionTrend.builder()
                        .date(row[0].toString())
                        .earned(((Number) row[1]).longValue())
                        .spend(((Number) row[2]).longValue())
                        .adjust(((Number) row[3]).longValue())
                        .build())
            .collect(Collectors.toList());

    return EcoPointStatisticsResponse.builder()
        .totalUsers(totalUsers)
        .usersByStatus(usersByStatus)
        .topUsers(topUsers)
        .totalTransactions(totalTransactions)
        .transactionsByType(transactionsByType)
        .transactionsBySource(transactionsBySource)
        .transactionTrend(trend)
        .build();
  }

  @Override
  public VoucherStatisticsResponse getVoucherStatistics() {
    Long totalCampaigns = voucherCampaignRepository.count();
    Long activeCampaigns = voucherCampaignRepository.countActiveCampaigns();
    Long totalVouchers = voucherRepository.count();

    Map<VoucherType, Long> vouchersByType =
        Arrays.stream(VoucherType.values())
            .collect(Collectors.toMap(type -> type, type -> voucherRepository.countByType(type)));

    Map<VoucherStatus, Long> vouchersByStatus =
        Arrays.stream(VoucherStatus.values())
            .collect(
                Collectors.toMap(
                    status -> status, status -> voucherRepository.countByStatus(status)));

    List<VoucherStatisticsResponse.TopVoucher> topAvailable =
        voucherRepository.findTopAvailableVouchers().stream()
            .map(
                row ->
                    VoucherStatisticsResponse.TopVoucher.builder()
                        .voucherId((Long) row[0])
                        .name((String) row[1])
                        .availableQuantity(((Number) row[2]).intValue())
                        .build())
            .collect(Collectors.toList());

    Long totalVoucherUsers = voucherUserRepository.count();
    Map<VoucherUserStatus, Long> voucherUsersByStatus =
        Arrays.stream(VoucherUserStatus.values())
            .collect(
                Collectors.toMap(
                    status -> status, status -> voucherUserRepository.countByStatus(status)));

    List<VoucherStatisticsResponse.TopUserVoucher> topUsers =
        voucherUserRepository.findTopUsers().stream()
            .map(
                row ->
                    VoucherStatisticsResponse.TopUserVoucher.builder()
                        .userId((Long) row[0])
                        .voucherCount(((Number) row[1]).longValue())
                        .build())
            .collect(Collectors.toList());

    Long totalRedemptions = voucherRedemptionRepository.count();
    BigDecimal totalDiscountValue = voucherRedemptionRepository.totalDiscountValue();

    List<VoucherStatisticsResponse.RedemptionTrend> redemptionTrend =
        voucherRedemptionRepository.redemptionTrend().stream()
            .map(
                row ->
                    VoucherStatisticsResponse.RedemptionTrend.builder()
                        .date(row[0].toString())
                        .redemptionCount(((Number) row[1]).longValue())
                        .discountValue((BigDecimal) row[2])
                        .build())
            .collect(Collectors.toList());

    return VoucherStatisticsResponse.builder()
        .totalCampaigns(totalCampaigns)
        .activeCampaigns(activeCampaigns)
        .totalVouchers(totalVouchers)
        .vouchersByType(vouchersByType)
        .vouchersByStatus(vouchersByStatus)
        .topAvailableVouchers(topAvailable)
        .totalVoucherUsers(totalVoucherUsers)
        .voucherUsersByStatus(voucherUsersByStatus)
        .topUsers(topUsers)
        .totalRedemptions(totalRedemptions)
        .totalDiscountValue(totalDiscountValue)
        .redemptionTrend(redemptionTrend)
        .build();
  }
}
