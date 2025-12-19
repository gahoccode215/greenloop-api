package com.greenloop.order.dto.response;

import com.greenloop.order.enums.OrderType;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.TransactionStatus;
import com.greenloop.order.enums.TransactionType;
import lombok.Builder;
import lombok.Data;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
@Builder
public class TransactionDetailResponse {

    // ========== BASIC INFO ==========
    private Long id;
    private String transactionCode;
    private String orderCode;
    private Long customerId;
    private String customerName;

    // ========== TRANSACTION TYPE ==========
    private TransactionType transactionType;  // PAYMENT / REFUND
    private OrderType orderType;              // ONLINE / OFFLINE

    // ========== AMOUNTS ==========
    private BigDecimal amount;                // Tổng tiền (+ vào, - ra)
    private AmountBreakdown breakdown;

    // ========== PAYMENT INFO ==========
    private PaymentMethod paymentMethod;      // COD, PAYOS, CASH, BANK_TRANSFER
    private String paymentDisplayName;        // "Tiền mặt", "Chuyển khoản", "COD", "PayOS"
    private String paymentTransactionId;

    // ========== STATUS ==========
    private TransactionStatus status;
    private String statusDisplayName;

    // ========== EVENT INFO ==========
    private Long eventId;
    private String eventName;

    // ========== CUSTOMER INFO ==========
    private Boolean isGuestPurchase;
    private String guestName;
    private String guestPhone;

    // ========== TIMESTAMPS ==========
    private LocalDateTime transactionDate;
    private LocalDateTime completedDate;
    private LocalDateTime refundedDate;

    // ========== DESCRIPTION ==========
    private String description;

    @Data
    @Builder
    public static class AmountBreakdown {
        private BigDecimal productTotal;          // Tiền hàng
        private BigDecimal shippingFee;           // Phí ship
        private BigDecimal discountAmount;        // Tổng giảm giá
        private BigDecimal voucherDiscount;       // Giảm từ voucher
        private BigDecimal shippingDiscount;      // Giảm phí ship
        private BigDecimal finalAmount;           // Tiền cuối cùng
    }
}
