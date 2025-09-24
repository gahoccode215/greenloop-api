package com.greeloop.user.service;

import com.greeloop.user.dto.request.LoginRequest;
import com.greeloop.user.dto.request.RefreshTokenRequest;
import com.greeloop.user.dto.request.RegisterRequest;
import com.greeloop.user.dto.response.AuthResponse;

public interface AuthService {

    AuthResponse login(LoginRequest request);

    AuthResponse register(RegisterRequest request);

    AuthResponse refreshToken(RefreshTokenRequest request, String oldAccessToken);

    void logout(String accessToken);
}

