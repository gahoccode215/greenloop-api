package com.greenloop.order.dto.request;

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
public class ShippingAddressRequest {

    @NotBlank(message = "Tên người nhận không được để trống")
    private String receiverName;

    @NotBlank(message = "Số điện thoại không được để trống")
    private String receiverPhone;

    @NotBlank(message = "Địa chỉ không được để trống")
    private String address;  // Số nhà, tên đường

    @NotNull(message = "Mã phường/xã không được để trống")
    private String wardCode;  // Mã phường/xã từ GHN

    @NotNull(message = "Mã quận/huyện không được để trống")
    private Integer districtId;  // Mã quận/huyện từ GHN

    @NotNull(message = "Mã tỉnh/thành không được để trống")
    private Integer provinceId;  // Mã tỉnh/thành từ GHN

    private String note;  // Ghi chú giao hàng (tùy chọn)
}
