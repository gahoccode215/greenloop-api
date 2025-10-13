package com.greenloop.user.service;


import com.greenloop.user.dto.response.UserProfileResponse;
import com.greenloop.user.entity.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import com.greenloop.user.dto.response.CreateEmployeeResponse;
import com.greenloop.user.dto.request.CreateEmployeeRequest;

import java.util.List;

public interface UserService extends UserDetailsService
{
    UserProfileResponse getMyProfile(Long userId);

    CreateEmployeeResponse createEmployee(CreateEmployeeRequest request);

    List<User> getAllUser();
}
