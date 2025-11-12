package com.greenloop.user.service;

import com.greenloop.user.dto.request.UpdateProfileRequest;
import com.greenloop.user.dto.response.UserProfileResponse;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.multipart.MultipartFile;

public interface UserService extends UserDetailsService {
  UserProfileResponse getMyProfile(Long userId);

  UserProfileResponse updateProfile(Long userId, UpdateProfileRequest request, MultipartFile avatar);
}
