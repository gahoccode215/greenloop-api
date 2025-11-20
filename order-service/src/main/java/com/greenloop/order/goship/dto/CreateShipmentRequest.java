package com.greenloop.order.goship.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CreateShipmentRequest {

    @JsonProperty("shipment")
    private ShipmentData shipment;

    @Data
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    public static class ShipmentData {

        @JsonProperty("rate")
        private String rate;

        @JsonProperty("order_id")
        private String orderId;

        @JsonProperty("payer")
        private Integer payer;

        @JsonProperty("address_from")
        private AddressData addressFrom;

        @JsonProperty("address_to")
        private AddressData addressTo;

        @JsonProperty("parcel")
        private ParcelData parcel;
    }

    @Data
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    public static class AddressData {

        @JsonProperty("name")
        private String name;

        @JsonProperty("phone")
        private String phone;

        @JsonProperty("street")
        private String street;

        @JsonProperty("ward")
        private String ward;

        @JsonProperty("district")
        private String district;

        @JsonProperty("city")
        private String city;
    }

    @Data
    @Builder
    @AllArgsConstructor
    @NoArgsConstructor
    public static class ParcelData {

        @JsonProperty("cod")
        private Long cod;

        @JsonProperty("amount")
        private Long amount;

        @JsonProperty("weight")
        private String weight;

        @JsonProperty("width")
        private String width;

        @JsonProperty("height")
        private String height;

        @JsonProperty("length")
        private String length;

        @JsonProperty("metadata")
        private String metadata;
    }
}
