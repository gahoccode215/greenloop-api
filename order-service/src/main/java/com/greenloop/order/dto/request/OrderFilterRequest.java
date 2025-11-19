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

    // Pagination
    private Integer page = 0;
    private Integer size = 10;
    private String sortBy = "createdAt";
    private String sortDirection = "DESC";

    // Filters
    private OrderStatus status;
    private PaymentStatus paymentStatus;
    private String searchKeyword;  // Tìm theo orderCode hoặc orderId
    private Long customerId;       // Filter theo customer ID
    private String customerEmail;  // Tìm theo email khách hàng
    private String customerName;   // Tìm theo tên khách hàng

    // Date range
    private String fromDate;  // Format: yyyy-MM-dd
    private String toDate;    // Format: yyyy-MM-dd
}
