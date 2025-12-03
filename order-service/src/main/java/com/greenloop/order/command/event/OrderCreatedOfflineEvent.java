package com.greenloop.order.command.event;

import com.greenloop.order.dto.request.OrderItemOfflineRequest;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.OrderType;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.util.List;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class OrderCreatedOfflineEvent {

    private String orderId;
    private String orderCode;
    private Long customerId;
    private Long eventId;

    // Voucher fields
    private Long voucherUserId;
    private String voucherCode;
    private BigDecimal discountAmount;

    private String guestName;
    private String guestPhone;

    private Boolean isGuestPurchase;

    private BigDecimal subTotal;
    private BigDecimal totalPrice;

    private OrderType orderType;
    private OrderStatus orderStatus;
    private PaymentStatus paymentStatus;
    private PaymentMethod paymentMethod;

    private List<OrderItemOfflineRequest> orderItems;

    private String note;
}
