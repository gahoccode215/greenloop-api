package com.greenloop.user.dto.response;

import com.fasterxml.jackson.annotation.JsonFormat;
import java.io.Serializable;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserProfileResponse implements Serializable {

  private Long userId;

  private String email;

  private String fullName;

  @JsonFormat(pattern = "yyyy-MM-dd")
  private LocalDate dateOfBirth;

  private String gender;

  private String phoneNumber;

  private String avatarUrl;

  private List<String> roles;

  private Boolean isActive;

  private Boolean isEmailVerified;

  private Integer ecoPoints;

  private String provider;

  @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
  private LocalDateTime createdAt;

  @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
  private LocalDateTime updatedAt;
}
