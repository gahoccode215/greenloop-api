package com.greenloop.reward.dto.response;

import com.greenloop.reward.enums.EcoPointStatus;
import com.greenloop.reward.enums.EcoPointType;
import com.greenloop.reward.enums.SourceType;
import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
@Builder
public class EcoPointStatisticsResponse {
    private Long totalUsers;
    private Map<EcoPointStatus, Long> usersByStatus;
    private List<TopUserPoints> topUsers;
    private Long totalTransactions;
    private Map<EcoPointType, Long> transactionsByType;
    private Map<SourceType, Long> transactionsBySource;
    private List<TransactionTrend> transactionTrend;

    @Data
    @Builder
    public static class TopUserPoints {
        private Long userId;
        private Integer totalPoints;
        private Integer lifetimePoints;
    }

    @Data
    @Builder
    public static class TransactionTrend {
        private String date;
        private Long earned;
        private Long spend;
        private Long adjust;
    }
}
