package com.greenloop.order.dto.response.order.offline;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class POSCustomerInfo {


    private String type;

    private Long customerId;

    private String name;

    private String phoneNumber;

    private String message;
}
