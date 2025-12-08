package com.greenloop.order.dto.request;

import lombok.*;
import jakarta.validation.constraints.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class WarehouseSettingRequest {

    @NotBlank(message = "Tên kho không được để trống")
    @Size(max = 100, message = "Tên kho không quá 100 ký tự")
    private String name;

    @NotBlank(message = "Số điện thoại không được để trống")
    @Pattern(regexp = "^0\\d{9}$", message = "Số điện thoại không hợp lệ")
    private String phone;

    @NotBlank(message = "Địa chỉ không được để trống")
    private String address;

    @NotNull(message = "Mã phường/xã không được để trống")
    private Long wardCode;

    @NotBlank(message = "Tên phường/xã không được để trống")
    private String wardName;

    @NotNull(message = "Mã quận/huyện không được để trống")
    private Integer districtId;

    @NotBlank(message = "Tên quận/huyện không được để trống")
    private String districtName;

    @NotNull(message = "Mã tỉnh/thành không được để trống")
    private Integer cityId;

    @NotBlank(message = "Tên tỉnh/thành không được để trống")
    private String cityName;
}
