package com.greenloop.order.dto.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CheckoutShippingAddressRequest {
    private String receiverName;
    private String receiverPhone;
    private String address;
    private String ward;
    private Long wardCode;
    private String districtName;
    private Integer districtId;
    private String cityName;
    private Integer cityId;
    private String note;
}
