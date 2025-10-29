package com.greenloop.user.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class CreateEmployeeRequest {

  @NotBlank(message = "Email không được để trống")
  @Email(message = "Email không hợp lệ")
  private String email;

  @NotBlank(message = "Họ và tên không được để trống")
  private String fullName;

  @Pattern(regexp = "^[0-9]{10,11}$", message = "Số điện thoại không hợp lệ")
  private String phoneNumber;

  @NotBlank(message = "Vai trò không được để trống")
  @Pattern(regexp = "^(STAFF|MANAGER)$", message = "Vai trò chỉ được là STAFF hoặc MANAGER")
  private String role;

  private String department; // HR, Operations, IT, Sales
}
