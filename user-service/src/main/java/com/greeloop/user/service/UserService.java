package com.greeloop.user.service;

import com.greeloop.user.dto.request.UpdateUserRequest;
import com.greeloop.user.dto.response.UserProfileResponse;
import com.greeloop.user.dto.response.UserResponse;
import org.springframework.data.domain.Page;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService extends UserDetailsService
{
    UserProfileResponse getMyProfile(Long userId);

    Page<UserResponse> getAllUsers(
            int page,
            int size,
            String sortBy,
            String sortDir,
            String email,
            String role,
            String currentUserRole
    );

    UserResponse getUserById(Long userId, String currentUserRole);

    UserResponse updateUser(Long userId, UpdateUserRequest request, String currentUserRole);

}
