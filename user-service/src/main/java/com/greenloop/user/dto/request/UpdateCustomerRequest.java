package com.greenloop.user.dto.request;

import com.greenloop.user.enums.Gender;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.LocalDate;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateCustomerRequest {

  @NotBlank(message = "Full name không được để trống")
  @Size(max = 100, message = "Full name tối đa 100 ký tự")
  private String fullName;

  @Email(message = "Email không hợp lệ")
  private String email;

  @Pattern(regexp = "^\\+?[0-9]{9,15}$", message = "Số điện thoại không hợp lệ")
  private String phoneNumber;

  private LocalDate dateOfBirth;

  private Gender gender;
}
