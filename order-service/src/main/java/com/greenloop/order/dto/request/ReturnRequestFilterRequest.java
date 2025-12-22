package com.greenloop.order.dto.request;

import com.greenloop.order.enums.ReturnRequestStatus;
import com.greenloop.order.enums.ReturnReason;
import com.greenloop.order.enums.ReturnType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ReturnRequestFilterRequest {

    private Integer page;

    private Integer size;

    private String sortBy;

    private String sortDirection;

    private ReturnRequestStatus status;

    private ReturnReason returnReason;

    private ReturnType returnType;

    private Long customerId;

    private String orderId;

    private String searchKeyword;

    private String fromDate;

    private String toDate;

    private BigDecimal minAmount;

    private BigDecimal maxAmount;
}
