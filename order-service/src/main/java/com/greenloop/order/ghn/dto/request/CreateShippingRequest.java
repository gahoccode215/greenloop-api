package com.greenloop.order.ghn.dto.request;

import jakarta.validation.Valid;
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
public class CreateShippingRequest {


    @Valid
    @NotNull(message = "Thông tin người gửi không được để trống")
    private SenderInfo senderInfo;


    private Integer orderWeight;
    private Integer orderLength;
    private Integer orderWidth;
    private Integer orderHeight;
    private Integer orderServiceType;
    private Integer orderPaymentType;
    private String orderRequireNote;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SenderInfo {
        @NotBlank(message = "Tên người gửi không được để trống")
        private String name;

        @NotBlank(message = "SĐT người gửi không được để trống")
        private String phone;

        @NotBlank(message = "Địa chỉ người gửi không được để trống")
        private String address;

        @NotBlank(message = "Phường/Xã người gửi không được để trống")
        private String wardName;

        @NotBlank(message = "Quận/Huyện người gửi không được để trống")
        private String districtName;

        @NotBlank(message = "Tỉnh/Thành người gửi không được để trống")
        private String provinceName;
    }
}
