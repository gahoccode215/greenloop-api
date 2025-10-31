package com.greenloop.user.service;

import com.greenloop.user.dto.request.CreateEmployeeRequest;
import com.greenloop.user.dto.response.CreateEmployeeResponse;
import com.greenloop.user.dto.response.UserProfileResponse;
import com.greenloop.user.entity.User;
import java.util.List;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService extends UserDetailsService {
  UserProfileResponse getMyProfile(Long userId);

}
