package com.greeloop.user.service.impl;

import com.greeloop.user.constant.RoleConstants;
import com.greeloop.user.dto.response.UserProfileResponse;
import com.greeloop.user.dto.response.UserResponse;
import com.greeloop.user.entity.Role;
import com.greeloop.user.entity.User;
import com.greeloop.user.exception.InvalidCredentialsException;
import com.greeloop.user.exception.UserNotFoundException;
import com.greeloop.user.repository.UserRepository;
import com.greeloop.user.service.BaseService;
import com.greeloop.user.service.UserService;
import com.greeloop.user.specification.GenericSpecifications;
import com.greeloop.user.specification.SpecificationBuilder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl extends BaseService<User, Long> implements UserService {

    private final UserRepository userRepository;

    @Override
    protected JpaRepository<User, Long> getRepository() {
        return userRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        log.debug("Loading user by email: {}", email);
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
    }

    @Override
    public UserProfileResponse getMyProfile(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(userId));

        log.info("Retrieved profile for user: {}", user.getEmail());

        return UserProfileResponse.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .role(user.getRole().getName())
                .isActive(user.getIsActive())
                .build();
    }

    @Override
    @Transactional(readOnly = true)
    public Page<UserResponse> getAllUsers(int page, int size, String sortBy, String sortDir, String email, String role, String currentUserRole) {
        log.info("Getting users list - page: {}, size: {}, role filter: {}, current user role: {}",
                page, size, role, currentUserRole);

        // Nếu có filter role thì validate quyền filter
        if (role != null && !role.trim().isEmpty()) {
            validateRoleAccess(currentUserRole, role);
        }

        // Tạo pageable
        Pageable pageable = createPageable(page, size, sortBy, sortDir);

        // Build specification với filter email và role
        SpecificationBuilder<User> builder = new SpecificationBuilder<>();

        if (email != null && !email.trim().isEmpty()) {
            builder.with(GenericSpecifications.fieldContains("email", email));
        }

        if (role != null && !role.trim().isEmpty()) {
            builder.with((root, query, cb) ->
                    cb.equal(root.get("role").get("name"), role)
            );
        } else {
            // Nếu không filter role, thì filter theo role của user hiện tại
            // ADMIN không bị giới hạn
            if (!RoleConstants.ADMIN.equals(currentUserRole)) {
                List<String> allowedRoles = switch (currentUserRole) {
                    case RoleConstants.MANAGER -> List.of(RoleConstants.STAFF, RoleConstants.USER);
                    case RoleConstants.STAFF -> List.of(RoleConstants.USER);
                    default -> throw new InvalidCredentialsException();
                };
                builder.with((root, query, cb) ->
                        root.get("role").get("name").in(allowedRoles)
                );
            }
        }

        Specification<User> spec = builder.build();

        // Thực thi query
        Page<User> usersPage = findAll(spec, pageable);

        log.info("Found {} users", usersPage.getTotalElements());

        return usersPage.map(this::mapToUserResponse);
    }


    @Override
    @Transactional(readOnly = true)
    public UserResponse getUserById(Long userId, String currentUserRole) {
        log.info("Getting user by ID: {} - requested by role: {}", userId, currentUserRole);

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException(userId));

        validateRoleAccess(currentUserRole, user.getRole().getName());

        log.info("Successfully retrieved user: {}", user.getEmail());

        return mapToUserResponse(user);
    }


    private void validateRoleAccess(String currentUserRole, String targetRole) {
        if (RoleConstants.ADMIN.equals(currentUserRole)) {
            return;
        }
        if (RoleConstants.MANAGER.equals(currentUserRole)) {
            if (!List.of(RoleConstants.STAFF, RoleConstants.USER).contains(targetRole)) {
                throw new InvalidCredentialsException();
            }
            return;
        }
        if (RoleConstants.STAFF.equals(currentUserRole)) {
            if (!RoleConstants.USER.equals(targetRole)) {
                throw new InvalidCredentialsException();
            }
            return;
        }
        throw new InvalidCredentialsException();
    }

    private UserResponse mapToUserResponse(User user) {
        return UserResponse.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .phoneNumber(user.getPhoneNumber())
                .role(user.getRole().getName())
                .isEmailVerified(user.getIsEmailVerified())
                .isActive(user.getIsActive())
                .createdAt(user.getCreatedAt())
                .build();
    }


}
