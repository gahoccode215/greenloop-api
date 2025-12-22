package com.greenloop.order.entity;

import com.greenloop.order.enums.OrderType;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.TransactionStatus;
import com.greenloop.order.enums.TransactionType;
import jakarta.persistence.*;
import lombok.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Table(name = "transactions", indexes = {
        @Index(name = "idx_transaction_order", columnList = "order_id"),
        @Index(name = "idx_transaction_customer", columnList = "customer_id"),
        @Index(name = "idx_transaction_type", columnList = "transaction_type"),
        @Index(name = "idx_transaction_status", columnList = "status"),
        @Index(name = "idx_transaction_date", columnList = "transaction_date"),
        @Index(name = "idx_transaction_order_type", columnList = "order_type"),
        @Index(name = "idx_transaction_payment_method", columnList = "payment_method"),
        @Index(name = "idx_transaction_event", columnList = "event_id"),
        @Index(name = "idx_transaction_return_request", columnList = "return_request_id") // MỚI
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Transaction {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "transaction_code", unique = true, nullable = false, length = 50)
    private String transactionCode;

    @Column(name = "order_id")
    private String orderId;

    @Column(name = "order_code", length = 50)
    private String orderCode;

    @Column(name = "customer_id")
    private Long customerId;

    @Enumerated(EnumType.STRING)
    @Column(name = "transaction_type", nullable = false, length = 50)
    private TransactionType transactionType;

    @Enumerated(EnumType.STRING)
    @Column(name = "order_type", length = 50)
    private OrderType orderType;

    @Column(name = "amount", nullable = false, precision = 15, scale = 2)
    private BigDecimal amount;

    // ========== CHI TIẾT BREAKDOWN ==========

    @Column(name = "product_total", precision = 15, scale = 2)
    private BigDecimal productTotal;

    @Column(name = "shipping_fee", precision = 15, scale = 2)
    private BigDecimal shippingFee;

    @Column(name = "discount_amount", precision = 15, scale = 2)
    private BigDecimal discountAmount;

    @Column(name = "voucher_code", length = 50)
    private String voucherCode;

    @Column(name = "voucher_discount", precision = 15, scale = 2)
    private BigDecimal voucherDiscount;

    @Column(name = "shipping_discount", precision = 15, scale = 2)
    private BigDecimal shippingDiscount;

    // ========== THÔNG TIN THANH TOÁN ==========

    @Enumerated(EnumType.STRING)
    @Column(name = "payment_method", length = 50)
    private PaymentMethod paymentMethod;

    @Column(name = "payment_order_code")
    private Long paymentOrderCode;

    @Column(name = "payment_transaction_id", length = 255)
    private String paymentTransactionId;

    // ========== TRẠNG THÁI ==========

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 50)
    private TransactionStatus status;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    // ========== THÔNG TIN SỰ KIỆN ==========

    @Column(name = "event_id")
    private Long eventId;

    @Column(name = "event_name", length = 200)
    private String eventName;

    // ========== THÔNG TIN KHÁCH ==========

    @Column(name = "is_guest_purchase")
    private Boolean isGuestPurchase;

    @Column(name = "guest_name", length = 100)
    private String guestName;

    @Column(name = "guest_phone", length = 20)
    private String guestPhone;

    // ========== THỜI GIAN ==========

    @Column(name = "transaction_date", nullable = false)
    private LocalDateTime transactionDate;

    @Column(name = "completed_date")
    private LocalDateTime completedDate;

    @Column(name = "refunded_date")
    private LocalDateTime refundedDate;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    // ========== THÔNG TIN TRẢ HÀNG (MỚI - CHO REFUND) ==========

    @Column(name = "return_request_id", length = 36)
    private String returnRequestId; // Link tới ReturnRequest

    @Column(name = "return_shipping_fee", precision = 15, scale = 2)
    private BigDecimal returnShippingFee; // Phí ship trả hàng (customer chịu)

    @Column(name = "transfer_proof_url", length = 500)
    private String transferProofUrl; // Ảnh bill chuyển khoản

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
        if (transactionDate == null) {
            transactionDate = LocalDateTime.now();
        }
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
