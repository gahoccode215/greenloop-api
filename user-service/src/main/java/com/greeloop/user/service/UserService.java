package com.greeloop.user.service;

import com.greeloop.user.dto.response.UserProfileResponse;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService extends UserDetailsService
{
    UserProfileResponse getMyProfile(Long userId);
}
