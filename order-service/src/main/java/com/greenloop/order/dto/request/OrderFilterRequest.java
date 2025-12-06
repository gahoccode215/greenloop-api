package com.greenloop.order.dto.request;

import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.OrderType;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OrderFilterRequest {

    private Integer page = 0;
    private Integer size = 10;
    private String sortBy = "createdAt";
    private String sortDirection = "DESC";

    private OrderStatus status;
    private PaymentStatus paymentStatus;
    private String searchKeyword;
    private Long customerId;
    private String customerEmail;
    private String customerName;
    private String fromDate;
    private String toDate;



    private OrderType orderType;

    private Long eventId;

    private Boolean isGuestPurchase;

    private PaymentMethod paymentMethod;

    private String createdBy;

    private BigDecimal minPrice;
    private BigDecimal maxPrice;
}
