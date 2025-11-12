package com.greenloop.user.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ResetPasswordRequest {
  @NotBlank(message = "Email không được để trống")
  @Email(message = "Email phải có định dạng hợp lệ")
  private String email;

  @NotBlank(message = "Mật khẩu mới không được để trống")
  private String newPassword;

  @NotBlank(message = "Xác nhận mật khẩu không được để trống")
  private String confirmPassword;
}
