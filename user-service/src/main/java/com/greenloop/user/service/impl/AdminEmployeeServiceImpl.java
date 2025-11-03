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
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
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
  private final String AVATAR_FOLDER = "GreenLoop/Employees/Avatars";

  @Override
  @Cacheable(value = "employees_list", key = "#pageable.pageNumber + '-' + #search + '-' + #status")
  public PageResponseDTO<EmployeeResponse> getEmployees(
      String search, String status, Pageable pageable) {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    boolean isAdmin =
        auth.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_" + RoleConstants.ADMIN));

    List<String> allowedRoles =
        isAdmin
            ? List.of(RoleConstants.STAFF, RoleConstants.MANAGER)
            : List.of(RoleConstants.STAFF);

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
  @Cacheable(value = "employee_detail", key = "#id")
  public EmployeeResponse getEmployeeDetail(Long id) {
    User user =
        userRepository
            .findById(id)
            .orElseThrow(() -> new EmployeeNotFoundException("Không tìm thấy nhân viên"));

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    boolean isAdmin =
        auth.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_" + RoleConstants.ADMIN));

    List<String> userRoles = user.getRoles().stream().map(Role::getName).toList();

    boolean isStaffOrManager =
        userRoles.contains(RoleConstants.STAFF) || userRoles.contains(RoleConstants.MANAGER);

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
  @CacheEvict(value = "employees_list", allEntries = true)
  public CreateEmployeeResponse createEmployee(
      CreateEmployeeRequest request, MultipartFile avatar) {
    log.info("Creating employee with email: {}", request.getEmail());

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    boolean isAdmin =
        auth.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_" + RoleConstants.ADMIN));

    if (!isAdmin && request.getRole().equals(RoleConstants.MANAGER)) {
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

    // Upload avatar nếu có
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
  @CacheEvict(
      value = {"employee_detail", "employees_list"},
      allEntries = true)
  public EmployeeResponse updateEmployee(
      Long id, UpdateEmployeeRequest request, MultipartFile avatar) {
    log.info("Updating employee with id: {}", id);

    User employee =
        userRepository
            .findById(id)
            .orElseThrow(() -> new EmployeeNotFoundException("Không tìm thấy nhân viên"));

    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    boolean isAdmin =
        auth.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_" + RoleConstants.ADMIN));

    List<String> currentRoles = employee.getRoles().stream().map(Role::getName).toList();

    boolean isStaffOrManager =
        currentRoles.contains(RoleConstants.STAFF) || currentRoles.contains(RoleConstants.MANAGER);

    if (!isStaffOrManager) {
      throw new EmployeeNotFoundException("Không tìm thấy nhân viên");
    }

    if (!isAdmin && currentRoles.contains(RoleConstants.MANAGER)) {
      throw new InvalidCredentialsException();
    }

    if (!isAdmin && request.getRole() != null && request.getRole().equals(RoleConstants.MANAGER)) {
      throw new InvalidCredentialsException();
    }

    // Update email
    if (request.getEmail() != null && !request.getEmail().equals(employee.getEmail())) {
      if (userRepository.existsByEmail(request.getEmail())) {
        throw new EmailAlreadyExistsException();
      }
      employee.setEmail(request.getEmail());
    }

    // Update phone
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

    // Update role
    if (request.getRole() != null && !currentRoles.contains(request.getRole())) {
      Role newRole =
          roleRepository
              .findByName(request.getRole())
              .orElseThrow(() -> new RoleNotFoundException(request.getRole()));
      employee.setRoles(List.of(newRole));
    }

    // Upload avatar mới nếu có
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
  @CacheEvict(
      value = {"employee_detail", "employees_list"},
      allEntries = true)
  public EmployeeResponse changeEmployeeStatus(Long id, Boolean isActive) {
    log.info("Changing employee status for id: {} to: {}", id, isActive);

    // Tìm employee
    User employee =
        userRepository
            .findById(id)
            .orElseThrow(() -> new EmployeeNotFoundException("Không tìm thấy nhân viên"));

    // Kiểm tra quyền
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    boolean isAdmin =
        auth.getAuthorities().stream()
            .anyMatch(a -> a.getAuthority().equals("ROLE_" + RoleConstants.ADMIN));

    List<String> currentRoles = employee.getRoles().stream().map(Role::getName).toList();

    // Kiểm tra employee có phải STAFF hoặc MANAGER không
    boolean isStaffOrManager =
        currentRoles.contains(RoleConstants.STAFF) || currentRoles.contains(RoleConstants.MANAGER);

    if (!isStaffOrManager) {
      throw new EmployeeNotFoundException("Không tìm thấy nhân viên");
    }

    // MANAGER không được thay đổi status của MANAGER khác
    if (!isAdmin && currentRoles.contains(RoleConstants.MANAGER)) {
      throw new InvalidCredentialsException();
    }

    // Kiểm tra nếu status không thay đổi
    if (employee.isActive() == isActive) {
      log.info("Employee status is already {}, no change needed", isActive);
      return mapUserToEmployeeResponse(employee);
    }

    // Thay đổi status
    employee.setActive(isActive);

    // Set updatedBy
    String currentUserId = auth.getPrincipal().toString();
    employee.setUpdatedBy(Long.parseLong(currentUserId));

    User updatedEmployee = userRepository.save(employee);

    log.info(
        "Employee status changed successfully for id: {}. New status: {}",
        id,
        isActive ? "ACTIVE" : "INACTIVE");

    return mapUserToEmployeeResponse(updatedEmployee);
  }

  /**
   * Xử lý upload avatar cho nhân viên. Nếu đã có avatar cũ, xóa ảnh cũ trước khi upload ảnh mới.
   */
  private void handleAvatarUpload(User user, MultipartFile file) {
    try {
      // Xóa ảnh cũ nếu có
      if (user.getMediaKey() != null) {
        cloudinaryService.deleteImage(user.getMediaKey());
      }

      // Upload ảnh mới
      Map<String, String> uploadResult =
          cloudinaryService.uploadImage(file.getBytes(), AVATAR_FOLDER);

      // Cập nhật URL và media key
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
