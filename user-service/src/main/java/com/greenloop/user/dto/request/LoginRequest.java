package com.greenloop.user.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class LoginRequest {
    @NotBlank(message = "Email không được để trống")
    @Email(message = "Email phải có định dạng hợp lệ")
    @Schema(
            description = "Email người dùng",
            example = "user@example.com",
            defaultValue = "admin"
    )
    private String email;

    @Schema(
            description = "Mật khẩu người dùng",
            example = "123456",
            defaultValue = "admin"
    )
    @NotBlank(message = "Mật khẩu không được để trống")
    private String password;
}