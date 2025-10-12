package com.greenloop.user.service;


import com.greenloop.user.dto.response.UserProfileResponse;
import org.springframework.security.core.userdetails.UserDetailsService;
import com.greenloop.user.dto.response.CreateEmployeeResponse;
import com.greenloop.user.dto.request.CreateEmployeeRequest;

public interface UserService extends UserDetailsService
{
    UserProfileResponse getMyProfile(Long userId);

    CreateEmployeeResponse createEmployee(CreateEmployeeRequest request);
}
