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

    @Column(name = "receiver_phone")
    private String receiverPhone;

    @Column(name = "receiver_address")
    private String receiverAddress;

    @Column(name = "receiver_ward_code")
    private Long receiverWardCode;

    @Column(name = "receiver_ward_name")
    private String receiverWardName;

    @Column(name = "receiver_district_name")
    private String receiverDistrictName;

    @Column(name = "receiver_district_id")
    private Integer receiverDistrictId;

    @Column(name = "receiver_city_name")
    private String receiverCityName;

    @Column(name = "receiver_city_id")
    private Integer receiverCityId;

    @Column(name = "shipping_note")
    private String note;

    @Column(name = "warehouse_name")
    private String warehouseName;

    @Column(name = "warehouse_phone")
    private String warehousePhone;

    @Column(name = "warehouse_address")
    private String warehouseAddress;

    @Column(name = "warehouse_ward_code")
    private Long warehouseWardCode;

    @Column(name = "warehouse_ward_name")
    private String warehouseWardName;

    @Column(name = "warehouse_district_id")
    private Integer warehouseDistrictId;

    @Column(name = "warehouse_district_name")
    private String warehouseDistrictName;

    @Column(name = "warehouse_city_id")
    private Integer warehouseCityId;

    @Column(name = "warehouse_city_name")
    private String warehouseCityName;
}
