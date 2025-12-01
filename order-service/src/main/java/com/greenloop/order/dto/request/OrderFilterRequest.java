package com.greenloop.order.dto.request;

import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.PaymentStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

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
}
