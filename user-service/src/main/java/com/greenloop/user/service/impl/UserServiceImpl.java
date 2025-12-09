package com.greenloop.user.service.impl;

import com.greenloop.user.client.RewardClient;
import com.greenloop.user.dto.request.UpdateProfileRequest;
import com.greenloop.user.dto.response.ApiResponseDTO;
import com.greenloop.user.dto.response.EcoPointResponse;
import com.greenloop.user.dto.response.UserProfileResponse;
import com.greenloop.user.entity.Role;
import com.greenloop.user.entity.User;
import com.greenloop.user.exception.PhoneNumberAlreadyExistsException;
import com.greenloop.user.exception.UserNotFoundException;
import com.greenloop.user.repository.UserRepository;
import com.greenloop.user.service.CloudinaryService;
import com.greenloop.user.service.UserService;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

  private final UserRepository userRepository;
  private final CloudinaryService cloudinaryService;
  private final RewardClient rewardClient;

  @Override
  @Transactional(readOnly = true)
  public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
    return userRepository
        .findByEmail(email)
        .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
  }

  @Override
  @Transactional(readOnly = true)
  public UserProfileResponse getMyProfile(Long userId) {
    User user =
        userRepository.findById(userId).orElseThrow(() -> new UserNotFoundException(userId));
    UserProfileResponse profile = mapUserToProfileResponse(user);
    try {
      log.info("Fetching eco points for user: {}", userId);

      ApiResponseDTO<EcoPointResponse> response = rewardClient.getMyEcoPoints(userId);

      if (response != null && response.getData() != null) {
        profile.setTotalEcoPoints(response.getData().getTotalPoints());
        profile.setLifetimeEcoPoints(response.getData().getLifetimePoints());
      }
    } catch (Exception e) {
      log.warn("Failed to fetch eco points for user {}: {}", userId, e.getMessage());
      profile.setTotalEcoPoints(0);
      profile.setLifetimeEcoPoints(0);
    }
    return profile;
  }

  @Override
  @Transactional
  public UserProfileResponse updateProfile(
      Long userId, UpdateProfileRequest request, MultipartFile avatar) {
    User user =
        userRepository.findById(userId).orElseThrow(() -> new UserNotFoundException(userId));
    if (request.getPhoneNumber() != null
        && !request.getPhoneNumber().equals(user.getPhone())
        && userRepository.existsByPhone(request.getPhoneNumber())) {
      throw new PhoneNumberAlreadyExistsException(request.getPhoneNumber());
    }
    if (request.getFullName() != null) {
      user.setFullName(request.getFullName());
    }
    if (request.getDateOfBirth() != null) {
      user.setDateOfBirth(request.getDateOfBirth());
    }
    if (request.getGender() != null) {
      user.setGender(request.getGender());
    }
    if (request.getPhoneNumber() != null) {
      user.setPhone(request.getPhoneNumber());
    }
    if (avatar != null && !avatar.isEmpty()) {
      handleAvatarUpload(user, avatar);
    }
    User updatedUser = userRepository.save(user);
    return mapUserToProfileResponse(updatedUser);
  }

    @Override
    public List<Long> getAllUserIds() {
      List<Long> userIds = new ArrayList<>();
        List<User> users = userRepository.findAll();
        for (User user : users) {
            userIds.add(user.getId());
        }
        return userIds;
    }

    private UserProfileResponse mapUserToProfileResponse(User user) {
    List<String> roleNames = user.getRoles().stream().map(Role::getName).toList();

    return UserProfileResponse.builder()
        .userId(user.getId())
        .email(user.getEmail())
        .fullName(user.getFullName())
        .dateOfBirth(user.getDateOfBirth())
        .gender(user.getGender() != null ? user.getGender().name() : null)
        .phoneNumber(user.getPhone())
        .avatarUrl(user.getAvatarUrl())
        .roles(roleNames)
        .isActive(user.isActive())
        .isEmailVerified(user.getIsEmailVerified())
        .provider(user.getProvider())
        .createdAt(user.getCreatedAt())
        .updatedAt(user.getUpdatedAt())
        .build();
  }

  private void handleAvatarUpload(User user, MultipartFile file) {
    try {
      if (user.getMediaKey() != null) {
        cloudinaryService.deleteImage(user.getMediaKey());
      }
      Map<String, String> uploadResult =
          cloudinaryService.uploadImage(file.getBytes(), "GreenLoop/Users/Avatars");
      user.setAvatarUrl(cloudinaryService.getImageUrl(uploadResult.get("asset_id")));
      user.setMediaKey(uploadResult.get("public_id"));
    } catch (Exception e) {
      throw new RuntimeException("Failed to upload avatar", e);
    }
  }
}
