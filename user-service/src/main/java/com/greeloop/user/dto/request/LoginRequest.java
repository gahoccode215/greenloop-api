package com.greeloop.user.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class LoginRequest {
    @NotBlank(message = "Email không được để trống")
    @Email(message = "Email phải có định dạng hợp lệ")
    private String email;

    @NotBlank(message = "Mật khẩu không được để trống")
    private String password;
}