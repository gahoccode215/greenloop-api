package com.greenloop.order.dto.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateShipmentRequestDTO {

    // Parcel Info - Optional (fallback to Order if null)
    private String weight;
    private String width;
    private String height;
    private String length;
    private String metadata;
    private String reason;


    private Long codAmount;

    private Long totalAmount;

    @NotNull(message = "Người trả phí ship không được để trống")
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

        @NotBlank(message = "Tên người nhận không được để trống")
        private String name;

        @NotBlank(message = "Số điện thoại không được để trống")
        private String phone;

        @NotBlank(message = "Địa chỉ không được để trống")
        private String street;

        @NotNull(message = "Mã phường/xã không được để trống")
        private String wardCode;

        @NotNull(message = "Mã quận/huyện không được để trống")
        private String districtId;

        @NotNull(message = "Mã tỉnh/thành phố không được để trống")
        private String cityId;
    }
}
