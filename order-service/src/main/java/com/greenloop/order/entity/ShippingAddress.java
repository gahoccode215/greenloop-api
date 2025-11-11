package com.greenloop.order.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Embeddable
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ShippingAddress {

    @Column(name = "receiver_name", length = 100)
    private String receiverName;

    @Column(name = "receiver_phone", length = 20)
    private String receiverPhone;

    @Column(name = "shipping_address", length = 500)
    private String receiverAddress;

    @Column(name = "ward_code", length = 20)
    private String receiverWardCode;

    @Column(name = "district_id")
    private Integer receiverDistrictId;

    @Column(name = "province_id")
    private Integer receiverProvinceId;

    @Column(name = "shipping_note", length = 500)
    private String note;
}
