package com.greenloop.reward.dto.response;

import com.greenloop.reward.enums.VoucherStatus;
import com.greenloop.reward.enums.VoucherType;
import com.greenloop.reward.enums.VoucherUserStatus;
import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

@Data
@Builder
public class VoucherStatisticsResponse {
    private Long totalCampaigns;
    private Long activeCampaigns;
    private Long totalVouchers;
    private Map<VoucherType, Long> vouchersByType;
    private Map<VoucherStatus, Long> vouchersByStatus;
    private List<TopVoucher> topAvailableVouchers;
    private Long totalVoucherUsers;
    private Map<VoucherUserStatus, Long> voucherUsersByStatus;
    private List<TopUserVoucher> topUsers;
    private Long totalRedemptions;
    private BigDecimal totalDiscountValue;
    private List<RedemptionTrend> redemptionTrend;

    @Data
    @Builder
    public static class TopVoucher {
        private Long voucherId;
        private String name;
        private Integer availableQuantity;
    }

    @Data
    @Builder
    public static class TopUserVoucher {
        private Long userId;
        private Long voucherCount;
    }

    @Data
    @Builder
    public static class RedemptionTrend {
        private String date;
        private Long redemptionCount;
        private BigDecimal discountValue;
    }
}
