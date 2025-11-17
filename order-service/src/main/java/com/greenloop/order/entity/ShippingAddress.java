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

    @Column(name = "receiver_address", length = 500)
    private String receiverAddress;

    @Column(name = "receiver_ward_code")
    private String receiverWardCode;

    @Column(name = "receiver_district_id")
    private Integer receiverDistrictId;

    @Column(name = "receiver_city_id")
    private Integer receiverCityId;

    @Column(name = "shipping_note", length = 500)
    private String note;

    @Column(name = "warehouse_name", length = 100)
    private String warehouseName;

    @Column(name = "warehouse_phone", length = 20)
    private String warehousePhone;

    @Column(name = "warehouse_address", length = 500)
    private String warehouseAddress;

    @Column(name = "warehouse_ward_code", length = 20)
    private String warehouseWardCode;

    @Column(name = "warehouse_district_id")
    private Integer warehouseDistrictId;

    @Column(name = "warehouse_city_id")
    private Integer warehouseCityId;

}
