package com.greeloop.user.service.impl;

import com.greeloop.user.dto.response.UserProfileResponse;
import com.greeloop.user.dto.response.UserResponse;
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
public class UserServiceImpl extends BaseService<User, Long> implements UserService
{

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
        // Validate role access
        validateRoleAccess(currentUserRole, role);

        // Get allowed roles based on current user role
        List<String> allowedRoles = getAllowedRoles(currentUserRole);

        // Create pageable
        Pageable pageable = createPageable(page, size, sortBy, sortDir);

        // Build specification with filters
        Specification<User> spec = buildUserSpecification(email, role, allowedRoles);

        // Execute query
        Page<User> usersPage = findAll(spec, pageable);

        log.info("Found {} users", usersPage.getTotalElements());

        return usersPage.map(this::mapToUserResponse);
    }
    private void validateRoleAccess(String currentUserRole, String requestedRole) {
        if ("MANAGER".equals(currentUserRole) && requestedRole != null) {
            List<String> allowedRoles = Arrays.asList("STAFF", "CUSTOMER");
            if (!allowedRoles.contains(requestedRole)) {
                throw new InvalidCredentialsException();
            }
        }

        if ("STAFF".equals(currentUserRole) && requestedRole != null && !"CUSTOMER".equals(requestedRole)) {
            throw new InvalidCredentialsException();
        }
    }

    private List<String> getAllowedRoles(String currentUserRole) {
        return switch (currentUserRole) {
            case "ADMIN" -> null; // null = all roles
            case "MANAGER" -> Arrays.asList("STAFF", "CUSTOMER");
            case "STAFF" -> Arrays.asList("CUSTOMER");
            default -> throw new InvalidCredentialsException();
        };
    }

    private Specification<User> buildUserSpecification(String email, String role, List<String> allowedRoles) {
        SpecificationBuilder<User> builder = new SpecificationBuilder<>();

        // Add email filter if provided
        if (email != null && !email.trim().isEmpty()) {
            builder.with(GenericSpecifications.fieldContains("email", email));
        }

        // Add role filter based on permissions
        if (allowedRoles == null) {
            // ADMIN - can filter by any role
            if (role != null && !role.trim().isEmpty()) {
                builder.with((root, query, cb) ->
                        cb.equal(root.get("role").get("name"), role)
                );
            }
        } else {
            // MANAGER/STAFF - restricted to allowed roles
            if (role != null && !role.trim().isEmpty()) {
                // Specific role requested (already validated)
                builder.with((root, query, cb) ->
                        cb.equal(root.get("role").get("name"), role)
                );
            } else {
                // Show all allowed roles
                builder.with((root, query, cb) ->
                        root.get("role").get("name").in(allowedRoles)
                );
            }
        }

        return builder.build();
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
