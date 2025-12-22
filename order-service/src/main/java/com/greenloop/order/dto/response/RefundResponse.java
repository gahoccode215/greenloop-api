package com.greenloop.order.dto.response;

import com.greenloop.order.dto.BankInfoDTO;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.TransactionStatus;
import lombok.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefundResponse {
    private Long transactionId;
    private String transactionCode;
    private String orderId;
    private String orderCode;
    private String returnRequestId;
    private Long customerId;

    private BigDecimal originalAmount;
    private BigDecimal returnShippingFee;
    private BigDecimal refundAmount;

    private PaymentMethod paymentMethod;
    private String paymentMethodText;
    private BankInfoDTO bankInfo;

    private TransactionStatus status;
    private String statusText;

    private String transferProofUrl;
    private String description;

    private LocalDateTime transactionDate;
    private LocalDateTime refundedDate;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
