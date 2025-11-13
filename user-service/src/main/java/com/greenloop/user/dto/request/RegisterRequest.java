package com.greenloop.user.dto.request;

import jakarta.validation.constraints.*;
import java.time.LocalDate;
import lombok.Data;

@Data
public class RegisterRequest {
  @NotBlank(message = "Email không được để trống")
  @Email(message = "Email không đúng định dạng")
  private String email;

  @NotBlank(message = "Họ và tên không được để trống")
  @Size(min = 2, max = 100, message = "Họ và tên phải có từ 2 đến 100 ký tự")
  private String fullName;

  @NotNull(message = "Ngày sinh không được để trống")
  @Past(message = "Ngày sinh phải là ngày trong quá khứ")
  private LocalDate dateOfBirth;

  @NotBlank(message = "Số điện thoại không được để trống")
  @Pattern(regexp = "^\\+?[0-9]{9,15}$", message = "Số điện thoại không hợp lệ")
  private String phoneNumber;

  @NotBlank(message = "Mật khẩu không được để trống")
  @Size(min = 6, message = "Mật khẩu phải có ít nhất 6 ký tự")
  private String password;

  @NotBlank(message = "Xác nhận mật khẩu không được để trống")
  private String confirmPassword;
}
