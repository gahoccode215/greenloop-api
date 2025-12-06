package com.greenloop.notification.dto.request;

import com.greenloop.notification.enums.Platform;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class TokenRequest {
    private Long userId;
    private  String token;
    private Platform platform;
}
