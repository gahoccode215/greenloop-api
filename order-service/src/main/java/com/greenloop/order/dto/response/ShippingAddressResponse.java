package com.greenloop.order.dto.response;

import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ShippingAddressResponse {

    // Receiver info
    private String receiverName;
    private String receiverPhone;
    private String receiverAddress;
    private String receiverWardName;
    private Long receiverWardCode;
    private String receiverDistrictName;
    private Integer receiverDistrictId;
    private String receiverCityName;
    private Integer receiverCityId;

    // Warehouse info
    private String warehouseName;
    private String warehousePhone;
    private String warehouseAddress;
    private String warehouseWardName;
    private Long warehouseWardCode;
    private String warehouseDistrictName;
    private Integer warehouseDistrictId;
    private String warehouseCityName;
    private Integer warehouseCityId;

    private String note;
}
