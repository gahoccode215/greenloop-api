package com.greenloop.user.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AddressRequest {

  @NotBlank(message = "Tên người nhận không được để trống")
  @Size(min = 2, max = 100, message = "Tên người nhận phải từ 2 đến 100 ký tự")
  private String recipientName;

  @NotBlank(message = "Số điện thoại không được để trống")
  @Pattern(
      regexp = "^(\\+84|84|0)(3[2-9]|5[6|8|9]|7[0|6-9]|8[1-9]|9[0-9])[0-9]{7}$",
      message = "Số điện thoại không đúng định dạng (VD: 0912345678 hoặc +84912345678)")
  private String recipientPhone;

  @NotBlank(message = "Địa chỉ chi tiết không được để trống")
  @Size(min = 5, max = 255, message = "Địa chỉ chi tiết phải từ 5 đến 255 ký tự")
  private String addressLine;

  @NotBlank(message = "Phường/Xã không được để trống")
  private String ward; // Tên phường/xã

  @NotNull(message = "Quận/Huyện không được để trống")
  private Long district;

  @NotBlank(message = "Tên quận/huyện không được để trống")
  private String districtName; // FE gửi kèm tên (mới thêm)

  @NotNull(message = "Tỉnh/Thành phố không được để trống")
  private Long city;

  @NotBlank(message = "Tên tỉnh/thành phố không được để trống")
  private String cityName; // FE gửi kèm tên (mới thêm)

  @Size(max = 255, message = "Ghi chú giao hàng không được quá 255 ký tự")
  private String deliveryNote;

  private Boolean isDefault = false;
}
