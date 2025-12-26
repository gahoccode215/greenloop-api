package com.greenloop.order.dto.request;

import com.greenloop.order.enums.OrderType;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.TransactionStatus;
import com.greenloop.order.enums.TransactionType;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class TransactionFilterRequest {

    // Thời gian
    private LocalDateTime fromDate;
    private LocalDateTime toDate;

    // Loại giao dịch
    private TransactionType transactionType; // PAYMENT, REFUND

    // Loại đơn hàng
    private OrderType orderType; // ONLINE, OFFLINE

    // Phương thức thanh toán
    private PaymentMethod paymentMethod; // COD, PAYOS, CASH, BANK_TRANSFER

    // Trạng thái
    private TransactionStatus status; // PENDING, COMPLETED, REFUNDED

    // Sự kiện
    private Long eventId;

    // Khách hàng
    private Long customerId;

    // Khách vãng lai
    private Boolean isGuestPurchase;

    // Tìm kiếm
    private String searchKeyword; // Tìm theo orderCode, transactionCode, customerName
}
