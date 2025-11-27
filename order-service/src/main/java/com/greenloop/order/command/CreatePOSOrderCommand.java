package com.greenloop.order.command;

import com.greenloop.order.dto.request.OrderItemRequest;
import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.OrderType;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.axonframework.modelling.command.TargetAggregateIdentifier;

import java.math.BigDecimal;
import java.util.List;


@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CreatePOSOrderCommand {

    @TargetAggregateIdentifier
    private String orderId;

    private String orderCode;

    private OrderType orderType;  // POS_OFFLINE

    // Customer info
    private Long customerId;  // null nếu GUEST
    private Boolean isGuestPurchase;

    // Event info
    private Long eventLocationId;
    private Long posStaffId;

    // Order details
    private BigDecimal totalPrice;
    private OrderStatus orderStatus;
    private PaymentStatus paymentStatus;
    private PaymentMethod paymentMethod;
    private Long paymentOrderCode;  // PayOS orderCode (nếu QR_CODE)

    private List<OrderItemRequest> orderItems;
}
