package com.greenloop.user.service.impl;

import com.greenloop.user.dto.request.CreateEmployeeRequest;
import com.greenloop.user.dto.response.CreateEmployeeResponse;
import com.greenloop.user.dto.response.UserProfileResponse;
import com.greenloop.user.entity.Role;
import com.greenloop.user.entity.User;
import com.greenloop.user.exception.EmailAlreadyExistsException;
import com.greenloop.user.exception.RoleNotFoundException;
import com.greenloop.user.exception.UserNotFoundException;
import com.greenloop.user.repository.RoleRepository;
import com.greenloop.user.repository.UserRepository;
import com.greenloop.user.service.UserService;
import com.greenloop.user.util.PasswordGenerator;

import java.util.List;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordGenerator passwordGenerator;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        log.debug("Loading user by email: {}", email);
        return userRepository
                .findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
    }

    @Override
    public UserProfileResponse getMyProfile(Long userId) {
        User user =
                userRepository.findById(userId).orElseThrow(() -> new UserNotFoundException(userId));

        log.info("Retrieved profile for user: {}", user.getEmail());

        return UserProfileResponse.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .role(user.getRole().getName())
                .isActive(user.getIsActive())
                .build();
    }

    @Override
    @Transactional
    public CreateEmployeeResponse createEmployee(CreateEmployeeRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException();
        }
        Role role =
                roleRepository
                        .findByName(request.getRole())
                        .orElseThrow(() -> new RoleNotFoundException(request.getRole()));
        String tempPassword = passwordGenerator.generateTemporaryPassword();
        log.info("Generated temporary password for {}: {}", request.getEmail(), tempPassword);
        User employee =
                User.builder()
                        .email(request.getEmail())
                        .fullName(request.getFullName())
                        .phoneNumber(request.getPhoneNumber())
                        .department(request.getDepartment())
                        .role(role)
                        .password(passwordEncoder.encode(tempPassword))
                        .provider("LOCAL")
                        .isActive(true)
                        .isEmailVerified(false)
                        .build();
        User savedEmployee = userRepository.save(employee);

        log.info("Employee {} created successfully", savedEmployee.getEmail());

        return CreateEmployeeResponse.builder()
                .id(savedEmployee.getId())
                .email(savedEmployee.getEmail())
                .fullName(savedEmployee.getFullName())
                .role(role.getName())
                .department(savedEmployee.getDepartment())
                .isActive(savedEmployee.getIsActive())
                .temporaryPassword(tempPassword)
                .message("Nhân viên đã được tạo. Vui lòng cung cấp mật khẩu tạm cho nhân viên.")
                .build();
    }

    @Override
    public List<User> getAllUser() {
        return userRepository.findAll();
    }
}
