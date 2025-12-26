package com.greenloop.order.dto.response;

import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
public class TransactionReportResponse {

    private LocalDateTime fromDate;
    private LocalDateTime toDate;

    // ========== TỔNG QUAN ==========
    private OverallSummary overall;

    // ========== PHÂN LOẠI THEO NGUỒN ==========
    private SourceBreakdown sourceBreakdown;

    // ========== PHÂN LOẠI THEO KÊNH THANH TOÁN ==========
    private PaymentBreakdown paymentBreakdown;

    // ========== PHÂN LOẠI THEO SỰ KIỆN ==========
    private List<EventBreakdown> eventBreakdowns;

    // ========== CHI TIẾT CÁC KHOẢN ==========
    private DetailedAmounts detailedAmounts;

    // ========== GIAO DỊCH GẦN NHẤT ==========
    private List<TransactionDetailResponse> recentTransactions;

    // ========================================
    // ========== NESTED CLASSES ==========
    // ========================================

    @Data
    @Builder
    public static class OverallSummary {
        private BigDecimal totalInflow;           // ✅ Tổng tiền VÀO
        private BigDecimal totalOutflow;          // ✅ Tổng tiền RA
        private BigDecimal netCashFlow;           // ✅ Tiền ròng (VÀO - RA)

        private Integer totalTransactions;        // Tổng số giao dịch
        private Integer inflowTransactions;       // Số giao dịch tiền vào
        private Integer outflowTransactions;      // Số giao dịch tiền ra
    }

    @Data
    @Builder
    public static class SourceBreakdown {
        private OnlineOfflineData online;
        private OnlineOfflineData offline;
    }

    @Data
    @Builder
    public static class OnlineOfflineData {
        private BigDecimal totalInflow;           // Tiền vào
        private BigDecimal totalOutflow;          // Tiền ra
        private BigDecimal netAmount;             // Tiền ròng
        private Integer transactionCount;         // Số giao dịch
        private Double percentage;                // % so với tổng
    }

    @Data
    @Builder
    public static class PaymentBreakdown {
        private List<PaymentMethodData> methods;
    }

    @Data
    @Builder
    public static class PaymentMethodData {
        private String paymentMethod;             // COD, PAYOS, CASH, BANK_TRANSFER
        private BigDecimal totalInflow;
        private BigDecimal totalOutflow;
        private BigDecimal netAmount;
        private Integer transactionCount;
        private Double percentage;
    }

    @Data
    @Builder
    public static class EventBreakdown {
        private Long eventId;
        private String eventName;
        private BigDecimal totalRevenue;          // Doanh thu tại sự kiện
        private BigDecimal totalRefund;           // Hoàn tiền
        private BigDecimal netRevenue;            // Doanh thu ròng
        private Integer transactionCount;
        private PaymentMethodSplit paymentSplit;  // Phân tách tiền mặt/chuyển khoản
    }

    @Data
    @Builder
    public static class PaymentMethodSplit {
        private BigDecimal cash;                  // Tiền mặt
        private BigDecimal bankTransfer;          // Chuyển khoản
        private BigDecimal cod;                   // COD
        private BigDecimal payos;                 // PayOS
    }

    @Data
    @Builder
    public static class DetailedAmounts {
        private BigDecimal totalProductRevenue;   // Tổng tiền hàng
        private BigDecimal totalShippingFee;      // Tổng phí ship
        private BigDecimal totalDiscount;         // Tổng giảm giá
        private BigDecimal totalVoucherDiscount;  // Giảm từ voucher
        private BigDecimal totalShippingDiscount; // Giảm phí ship
        private BigDecimal totalRefund;           // Tổng hoàn tiền
    }
}
