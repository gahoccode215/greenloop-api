package com.greenloop.order.dto.response;

import com.greenloop.order.dto.BankInfoDTO;
import com.greenloop.order.enums.RefundMethod;
import com.greenloop.order.enums.RefundStatus;
import lombok.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefundTransactionResponse {
    private String refundId;
    private String orderId;
    private String orderCode;
    private String returnRequestId;
    private Long customerId;

    // Số tiền
    private BigDecimal originalAmount;
    private BigDecimal returnShippingFee;
    private BigDecimal refundAmount;

    // Phương thức
    private RefundMethod refundMethod;
    private String refundMethodText;
    private BankInfoDTO bankInfo;

    // Trạng thái
    private RefundStatus status;
    private String statusText;

    // Chứng từ
    private String transferProofUrl;
    private String note;

    // Timeline
    private LocalDateTime transferredAt;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
