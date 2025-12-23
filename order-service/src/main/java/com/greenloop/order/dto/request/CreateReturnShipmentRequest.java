package com.greenloop.order.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateReturnShipmentRequest {

    private String weight;
    private String width;
    private String height;
    private String length;
    private String metadata;
    private String reason;

    @NotNull(message = "Payer không được để trống")
    private Integer payer;

    @Valid
    private AddressOverrideDTO warehouseAddress;

    @Valid
    private AddressOverrideDTO customerAddress;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AddressOverrideDTO {

        private String name;
        private String phone;
        private String street;
        private String wardCode;
        private String districtId;
        private String cityId;
    }
}
