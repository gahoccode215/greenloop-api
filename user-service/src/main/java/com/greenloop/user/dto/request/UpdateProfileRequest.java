package com.greenloop.user.dto.request;

import com.greenloop.user.enums.Gender;
import jakarta.validation.constraints.Pattern;
import java.time.LocalDate;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UpdateProfileRequest {

  private String fullName;

  private LocalDate dateOfBirth;

  private Gender gender;

  @Pattern(regexp = "^[0-9]{10,20}$", message = "Số điện thoại phải có 10-20 chữ số")
  private String phoneNumber;
}
