package com.greenloop.order.goship.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateShipmentRequest {

    @JsonProperty("shipment")
    private ShipmentInfo shipment;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ShipmentInfo {

        @JsonProperty("address_from")
        private AddressInfo addressFrom;

        @JsonProperty("address_to")
        private AddressInfo addressTo;

        @JsonProperty("parcel")
        private ParcelInfo parcel;

        @JsonProperty("cod_amount")
        private BigDecimal codAmount;

        @JsonProperty("note")
        private String note;

        @JsonProperty("carrier")
        private String carrier; // Tùy chọn chỉ định carrier (vtp, ghn, njv...)
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AddressInfo {

        @JsonProperty("city")
        private String city; // City ID

        @JsonProperty("district")
        private String district; // District ID

        @JsonProperty("ward")
        private String ward; // Ward ID

        @JsonProperty("address")
        private String address;

        @JsonProperty("name")
        private String name;

        @JsonProperty("phone")
        private String phone;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ParcelInfo {

        @JsonProperty("weight")
        private Integer weight; // gram

        @JsonProperty("length")
        private Integer length; // cm

        @JsonProperty("width")
        private Integer width; // cm

        @JsonProperty("height")
        private Integer height; // cm

        @JsonProperty("converted_weight")
        private Integer convertedWeight; // Khối lượng quy đổi
    }
}
