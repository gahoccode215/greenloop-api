package com.greenloop.user.dto.request;

import com.greenloop.user.enums.Gender;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import java.time.LocalDate;
import lombok.Data;

@Data
public class UpdateEmployeeRequest {

  @Email(message = "Email không hợp lệ")
  private String email;

  private String fullName;

  @Pattern(regexp = "^\\+?[0-9]{9,15}$", message = "Số điện thoại không hợp lệ")
  private String phone;

  private LocalDate dateOfBirth;

  private Gender gender;

  @Pattern(regexp = "^(STAFF|MANAGER)$", message = "Role chỉ được là STAFF, MANAGER")
  private String role;

  private Boolean isActive;
}
