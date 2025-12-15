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
public class CalculateRateRequest {

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
    }


    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AddressInfo {

        @JsonProperty("district")
        private String district;

        @JsonProperty("city")
        private String city;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ParcelInfo {

        @JsonProperty("cod")
        private Long cod;

        @JsonProperty("amount")
        private Long amount;

        @JsonProperty("width")
        private Integer width;

        @JsonProperty("height")
        private Integer height;

        @JsonProperty("length")
        private Integer length;

        @JsonProperty("weight")
        private Integer weight;
    }
}
