package com.greenloop.reward.service;

import com.greenloop.reward.dto.request.CreateVoucherCampaignRequest;
import com.greenloop.reward.dto.request.CreateVoucherRequest;
import com.greenloop.reward.dto.request.RedeemVoucherRequest;
import com.greenloop.reward.dto.response.*;
import com.greenloop.reward.enums.VoucherStatus;
import com.greenloop.reward.enums.VoucherType;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import org.springframework.data.domain.Page;

public interface VoucherService {
  Long createVoucherCampaign(CreateVoucherCampaignRequest request);

  Long createVoucher(CreateVoucherRequest request);

  void updateVoucherCampaign(CreateVoucherCampaignRequest request, Long campaignId);

  void updateVoucher(CreateVoucherRequest request, Long voucherId);

  void changeVoucherStatus(Long voucherId, VoucherStatus status);

  void toggleVoucherStatus(Long voucherId);

  Page<VoucherCampaignResponse> getVoucherCampaignsForCustomer(
      String name, LocalDateTime from, LocalDateTime to, int page, int size);

  Page<VoucherCampaignResponse> getVoucherCampaignsForAdmin(
      String name, LocalDateTime from, LocalDateTime to, int page, int size);

  Page<VoucherResponse> getVouchersForAdmin(
      Long campaignId,
      String code,
      String name,
      VoucherType voucherType,
      VoucherStatus status,
      BigDecimal minOrderValue,
      BigDecimal maxDiscount,
      Boolean active,
      int page,
      int size);

  Page<VoucherResponse> getVouchersForCustomer(
      Long campaignId,
      String code,
      String name,
      VoucherType voucherType,
      VoucherStatus status,
      BigDecimal minOrderValue,
      BigDecimal maxDiscount,
      int page,
      int size);

  Long redeemVoucher(Long voucherId);

  List<UserVoucherResponse> myVouchers();

  UserVoucherResponse validateVoucherUsage(Long voucherId);

  void redeemVoucher(RedeemVoucherRequest request);

  List<VoucherExportDTO> getExportDataVoucher(
      Long campaignId,
      VoucherStatus status,
      VoucherType type,
      LocalDateTime expiryDateFrom,
      LocalDateTime expiryDateTo,
      Integer minPointToRedeem,
      Integer maxPointToRedeem,
      boolean includeExpired);

  List<VoucherCampaignExportDTO> getExportDataCampaign(
      LocalDateTime startDateFrom,
      LocalDateTime startDateTo,
      LocalDateTime endDateFrom,
      LocalDateTime endDateTo,
      boolean includeExpired,
      boolean includeVoucherDetails);
}
