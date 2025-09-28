package com.greeloop.user.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class RoleNotFoundException extends BusinessException {
    private final String roleName;

    public RoleNotFoundException(String roleName) {
        super("Không tìm thấy Role: " + roleName, HttpStatus.INTERNAL_SERVER_ERROR, "ROLE_NOT_FOUND");
        this.roleName = roleName;
    }
}
