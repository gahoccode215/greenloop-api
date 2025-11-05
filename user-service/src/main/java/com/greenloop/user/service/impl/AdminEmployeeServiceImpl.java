package com.greenloop.user.service.impl;

import com.greenloop.user.constant.RoleConstants;
import com.greenloop.user.dto.request.CreateEmployeeRequest;
import com.greenloop.user.dto.request.UpdateEmployeeRequest;
import com.greenloop.user.dto.response.CreateEmployeeResponse;
import com.greenloop.user.dto.response.EmployeeResponse;
import com.greenloop.user.dto.response.PageResponseDTO;
import com.greenloop.user.entity.Role;
import com.greenloop.user.entity.User;
import com.greenloop.user.exception.*;
import com.greenloop.user.repository.RoleRepository;
import com.greenloop.user.repository.UserRepository;
import com.greenloop.user.service.AdminEmployeeService;
import com.greenloop.user.service.CloudinaryService;
import com.greenloop.user.util.PageResponseUtil;
import com.greenloop.user.util.PasswordGeneratorUtil;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.Predicate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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
import org.springframework.web.multipart.MultipartFile;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminEmployeeServiceImpl implements AdminEmployeeService {

  private final UserRepository userRepository;
  private final RoleRepository roleRepository;
  private final PasswordEncoder passwordEncoder;
  private final PasswordGeneratorUtil passwordGeneratorUtil;
  private final CloudinaryService cloudinaryService;

  @Override
  public PageResponseDTO<EmployeeResponse> getEmployees(
      String search, String status, Pageable pageable) {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    String currentUserRole = getCurrentUserRole(auth);

    List<String> allowedRoles = getAllowedRolesToView(currentUserRole);

    Specification<User> spec =
        (root, query, cb) -> {
          List<Predicate> predicates = new ArrayList<>();

          Join<Object, Object> roleJoin = root.join("roles");
          predicates.add(roleJoin.get("name").in(allowedRoles));

          query.distinct(true);

          if (search != null && !search.isEmpty()) {
            String searchPattern = "%" + search.toLowerCase() + "%";
            predicates.add(
                cb.or(
                    cb.like(cb.lower(root.get("email")), searchPattern),
                    cb.like(cb.lower(root.get("fullName")), searchPattern),
                    cb.like(cb.lower(root.get("phone")), searchPattern)));
          }

          if (status != null && !status.isEmpty()) {
            predicates.add(cb.equal(root.get("isActive"), Boolean.valueOf(status)));
          }

          return cb.and(predicates.toArray(new Predicate[0]));
        };

    Page<EmployeeResponse> page =
        userRepository.findAll(spec, pageable).map(this::mapUserToEmployeeResponse);

    return PageResponseUtil.toPageResponse(page);
  }

  @Override
  public EmployeeResponse getEmployeeDetail(Long id) {
    User user =
        userRepository
            .findById(id)
            .orElseThrow(() -> new EmployeeNotFoundException("Không tìm thấy nhân viên"));

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    String currentUserRole = getCurrentUserRole(auth);
    List<String> userRoles = user.getRoles().stream().map(Role::getName).toList();

    validateEmployeeAccess(currentUserRole, userRoles);

    return mapUserToEmployeeResponse(user);
  }

  @Override
  @Transactional
  public CreateEmployeeResponse createEmployee(
      CreateEmployeeRequest request, MultipartFile avatar) {
    log.info("Creating employee with email: {}", request.getEmail());

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    String currentUserRole = getCurrentUserRole(auth);

    if (!isAdmin(currentUserRole) && !isManager(currentUserRole)) {
      throw new InvalidCredentialsException();
    }

    if (!isAdmin(currentUserRole) && request.getRole().equals(RoleConstants.ADMIN)) {
      throw new InvalidCredentialsException();
    }

    if (isManager(currentUserRole) && !isAllowedRoleForManager(request.getRole())) {
      throw new InvalidCredentialsException();
    }

    if (userRepository.existsByEmail(request.getEmail())) {
      throw new EmailAlreadyExistsException();
    }

    if (request.getPhone() != null
        && !request.getPhone().isEmpty()
        && userRepository.existsByPhone(request.getPhone())) {
      throw new PhoneNumberAlreadyExistsException(request.getPhone());
    }

    String temporaryPassword = passwordGeneratorUtil.generateSecurePassword();

    Role role =
        roleRepository
            .findByName(request.getRole())
            .orElseThrow(() -> new RoleNotFoundException(request.getRole()));

    User user =
        User.builder()
            .email(request.getEmail())
            .password(passwordEncoder.encode(temporaryPassword))
            .fullName(request.getFullName())
            .phone(request.getPhone())
            .isEmailVerified(true)
            .isActive(true)
            .isFirstLogin(true)
            .roles(List.of(role))
            .build();

    if (avatar != null && !avatar.isEmpty()) {
      handleAvatarUpload(user, avatar);
    }

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

  @Override
  @Transactional
  public EmployeeResponse updateEmployee(
      Long id, UpdateEmployeeRequest request, MultipartFile avatar) {
    log.info("Updating employee with id: {}", id);

    User employee =
        userRepository
            .findById(id)
            .orElseThrow(() -> new EmployeeNotFoundException("Không tìm thấy nhân viên"));

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    String currentUserRole = getCurrentUserRole(auth);
    List<String> employeeRoles = employee.getRoles().stream().map(Role::getName).toList();

    validateEmployeeAccess(currentUserRole, employeeRoles);

    if (request.getRole() != null && !employeeRoles.contains(request.getRole())) {
      if (!isAdmin(currentUserRole) && !isManager(currentUserRole)) {
        throw new InvalidCredentialsException();
      }
      if (isManager(currentUserRole) && !isAllowedRoleForManager(request.getRole())) {
        throw new InvalidCredentialsException();
      }
    }

    if (request.getEmail() != null && !request.getEmail().equals(employee.getEmail())) {
      if (userRepository.existsByEmail(request.getEmail())) {
        throw new EmailAlreadyExistsException();
      }
      employee.setEmail(request.getEmail());
    }

    if (request.getPhone() != null && !request.getPhone().equals(employee.getPhone())) {
      if (userRepository.existsByPhone(request.getPhone())) {
        throw new PhoneNumberAlreadyExistsException(request.getPhone());
      }
      employee.setPhone(request.getPhone());
    }

    if (request.getFullName() != null) {
      employee.setFullName(request.getFullName());
    }

    if (request.getDateOfBirth() != null) {
      employee.setDateOfBirth(request.getDateOfBirth());
    }

    if (request.getGender() != null) {
      employee.setGender(request.getGender());
    }

    if (request.getIsActive() != null) {
      employee.setActive(request.getIsActive());
    }

    if (request.getRole() != null && !employeeRoles.contains(request.getRole())) {
      Role newRole =
          roleRepository
              .findByName(request.getRole())
              .orElseThrow(() -> new RoleNotFoundException(request.getRole()));
      employee.setRoles(List.of(newRole));
    }

    if (avatar != null && !avatar.isEmpty()) {
      handleAvatarUpload(employee, avatar);
    }

    String currentUserId = auth.getPrincipal().toString();
    employee.setUpdatedBy(Long.parseLong(currentUserId));

    User updatedEmployee = userRepository.save(employee);

    log.info("Employee updated successfully with id: {}", updatedEmployee.getId());

    return mapUserToEmployeeResponse(updatedEmployee);
  }

  @Override
  @Transactional
  public EmployeeResponse changeEmployeeStatus(Long id, Boolean isActive) {
    log.info("Changing employee status for id: {} to: {}", id, isActive);

    User employee =
        userRepository
            .findById(id)
            .orElseThrow(() -> new EmployeeNotFoundException("Không tìm thấy nhân viên"));

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    String currentUserRole = getCurrentUserRole(auth);
    List<String> employeeRoles = employee.getRoles().stream().map(Role::getName).toList();

    validateEmployeeAccess(currentUserRole, employeeRoles);

    if (employee.isActive() == isActive) {
      log.info("Employee status is already {}, no change needed", isActive);
      return mapUserToEmployeeResponse(employee);
    }

    employee.setActive(isActive);

    String currentUserId = auth.getPrincipal().toString();
    employee.setUpdatedBy(Long.parseLong(currentUserId));

    User updatedEmployee = userRepository.save(employee);

    log.info(
        "Employee status changed successfully for id: {}. New status: {}",
        id,
        isActive ? "ACTIVE" : "INACTIVE");

    return mapUserToEmployeeResponse(updatedEmployee);
  }

  private String getCurrentUserRole(Authentication auth) {
    return auth.getAuthorities().stream()
        .map(a -> a.getAuthority().replace("ROLE_", ""))
        .findFirst()
        .orElseThrow(InvalidCredentialsException::new);
  }

  private List<String> getAllowedRolesToView(String currentUserRole) {
    return switch (currentUserRole) {
      case RoleConstants.ADMIN ->
          List.of(RoleConstants.MANAGER, RoleConstants.STORE_MANAGER, RoleConstants.STAFF);
      case RoleConstants.MANAGER -> List.of(RoleConstants.STORE_MANAGER, RoleConstants.STAFF);
      default -> throw new InvalidCredentialsException();
    };
  }

  private void validateEmployeeAccess(String currentUserRole, List<String> employeeRoles) {
    if (!isAdmin(currentUserRole) && !isManager(currentUserRole)) {
      throw new InvalidCredentialsException();
    }

    String employeeRole = employeeRoles.get(0);

    if (isManager(currentUserRole)) {
      boolean isAllowed =
          employeeRole.equals(RoleConstants.STAFF)
              || employeeRole.equals(RoleConstants.STORE_MANAGER);
      if (!isAllowed) {
        throw new InvalidCredentialsException();
      }
    }
  }

  private boolean isAllowedRoleForManager(String role) {
    return role.equals(RoleConstants.STAFF) || role.equals(RoleConstants.STORE_MANAGER);
  }

  private boolean isAdmin(String role) {
    return role.equals(RoleConstants.ADMIN);
  }

  private boolean isManager(String role) {
    return role.equals(RoleConstants.MANAGER);
  }

  private void handleAvatarUpload(User user, MultipartFile file) {
    try {
      if (user.getMediaKey() != null) {
        cloudinaryService.deleteImage(user.getMediaKey());
      }

      String AVATAR_FOLDER = "GreenLoop/Employees/Avatars";
      Map<String, String> uploadResult =
          cloudinaryService.uploadImage(file.getBytes(), AVATAR_FOLDER);

      user.setAvatarUrl(cloudinaryService.getImageUrl(uploadResult.get("asset_id")));
      user.setMediaKey(uploadResult.get("public_id"));

      log.info("Avatar uploaded successfully for user: {}", user.getEmail());
    } catch (Exception e) {
      log.error("Error uploading avatar for user {}: {}", user.getEmail(), e.getMessage(), e);
      throw new RuntimeException("Failed to upload avatar", e);
    }
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
