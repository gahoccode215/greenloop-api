package com.greenloop.user.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UpdateEmployeeRequest {


    @Size(min = 2, max = 50)
    private String firstName;

    @Size(min = 2, max = 50)
    private String lastName;

    @Pattern(regexp = "^[0-9]{10,11}$", message = "Invalid phone number")
    private String phoneNumber;

    private String department;

    private String roleName;

    private Boolean isActive;
}

