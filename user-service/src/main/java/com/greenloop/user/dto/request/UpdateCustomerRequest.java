package com.greenloop.user.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
public class UpdateCustomerRequest {
    @NotBlank
    private String firstName;
    @NotBlank
    private String lastName;
    private String phoneNumber;
    private String avatarUrl;
    private LocalDate dateOfBirth;
}
