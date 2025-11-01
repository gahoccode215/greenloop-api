package com.greenloop.user.service.impl;

import com.greenloop.user.constant.RoleConstants;
import com.greenloop.user.dto.request.CreateEmployeeRequest;
import com.greenloop.user.dto.response.CreateEmployeeResponse;
import com.greenloop.user.dto.response.EmployeeResponse;
import com.greenloop.user.dto.response.PageResponseDTO;
import com.greenloop.user.entity.Role;
import com.greenloop.user.entity.User;
import com.greenloop.user.exception.*;
import com.greenloop.user.repository.RoleRepository;
import com.greenloop.user.repository.UserRepository;
import com.greenloop.user.service.AdminEmployeeService;
import com.greenloop.user.util.PageResponseUtil;
import com.greenloop.user.util.PasswordGeneratorUtil;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.Predicate;
import java.util.ArrayList;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminEmployeeServiceImpl implements AdminEmployeeService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordGeneratorUtil passwordGeneratorUtil;

    @Override
    public PageResponseDTO<EmployeeResponse> getEmployees(String search, String status, Pageable pageable) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        boolean isAdmin = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_" + RoleConstants.ADMIN));

        List<String> allowedRoles = isAdmin
                ? List.of(RoleConstants.STAFF, RoleConstants.MANAGER)
                : List.of(RoleConstants.STAFF);

        Specification<User> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            Join<Object, Object> roleJoin = root.join("roles");
            predicates.add(roleJoin.get("name").in(allowedRoles));

            query.distinct(true);

            if (search != null && !search.isEmpty()) {
                String searchPattern = "%" + search.toLowerCase() + "%";
                predicates.add(cb.or(
                        cb.like(cb.lower(root.get("email")), searchPattern),
                        cb.like(cb.lower(root.get("fullName")), searchPattern),
                        cb.like(cb.lower(root.get("phone")), searchPattern)
                ));
            }

            if (status != null && !status.isEmpty()) {
                predicates.add(cb.equal(root.get("isActive"), Boolean.valueOf(status)));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };

        Page<EmployeeResponse> page = userRepository.findAll(spec, pageable)
                .map(this::mapUserToEmployeeResponse);

        return PageResponseUtil.toPageResponse(page);
    }

    @Override
    public EmployeeResponse getEmployeeDetail(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new EmployeeNotFoundException("Không tìm thấy nhân viên"));

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        boolean isAdmin = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_" + RoleConstants.ADMIN));

        List<String> userRoles = user.getRoles().stream()
                .map(Role::getName)
                .toList();

        boolean isStaffOrManager = userRoles.contains(RoleConstants.STAFF)
                || userRoles.contains(RoleConstants.MANAGER);

        if (!isStaffOrManager) {
            throw new EmployeeNotFoundException("Không tìm thấy nhân viên");
        }

        if (!isAdmin && userRoles.contains(RoleConstants.MANAGER)) {
            throw new EmployeeNotFoundException("Không có quyền xem thông tin quản lý");
        }

        return mapUserToEmployeeResponse(user);
    }

    @Override
    @Transactional
    public CreateEmployeeResponse createEmployee(CreateEmployeeRequest request) {
        log.info("Creating employee with email: {}", request.getEmail());

        // Kiểm tra quyền
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        boolean isAdmin = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_" + RoleConstants.ADMIN));

        if (!isAdmin && request.getRole().equals(RoleConstants.MANAGER)) {
            throw new InvalidCredentialsException();
        }

        // Validate email unique
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException();
        }

        // Validate phone unique
        if (request.getPhone() != null && !request.getPhone().isEmpty()
                && userRepository.existsByPhone(request.getPhone())) {
            throw new PhoneNumberAlreadyExistsException(request.getPhone());
        }

        // Generate temporary password
        String temporaryPassword = passwordGeneratorUtil.generateSecurePassword();

        // Get role
        Role role = roleRepository.findByName(request.getRole())
                .orElseThrow(() -> new RoleNotFoundException(request.getRole()));

        // Create user
        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(temporaryPassword))
                .fullName(request.getFullName())
                .phone(request.getPhone())
                .isEmailVerified(true)
                .isActive(true)
                .isFirstLogin(true)
                .roles(List.of(role))
                .build();

        User savedUser = userRepository.save(user);

        log.info("Employee created successfully with id: {}", savedUser.getId());

        return CreateEmployeeResponse.builder()
                .id(savedUser.getId())
                .email(savedUser.getEmail())
                .fullName(savedUser.getFullName())
                .phoneNumber(savedUser.getPhone())
                .role(request.getRole())
                .temporaryPassword(temporaryPassword)
                .isActive(savedUser.isActive())
                .isEmailVerified(savedUser.getIsEmailVerified())
                .build();
    }

    private EmployeeResponse mapUserToEmployeeResponse(User user) {
        return EmployeeResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .fullName(user.getFullName())
                .phoneNumber(user.getPhone())
                .dateOfBirth(user.getDateOfBirth())
                .gender(user.getGender())
                .avatarUrl(user.getAvatarUrl())
                .isActive(user.isActive())
                .roles(user.getRoles().stream().map(Role::getName).toList())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .build();
    }
}
