package com.greenloop.user.config;

import com.greenloop.user.constant.RoleConstants;
import com.greenloop.user.entity.Role;
import com.greenloop.user.entity.User;
import com.greenloop.user.repository.RoleRepository;
import com.greenloop.user.repository.UserRepository;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class DataInit implements CommandLineRunner {
  private final RoleRepository roleRepository;
  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;

  @Override
  public void run(String... args) throws Exception {
    initializeRoles();
    initializeUsers();
  }

  private void initializeRoles() {
    createRoleIfNotExists(RoleConstants.CUSTOMER, RoleConstants.CUSTOMER_DESC);
    createRoleIfNotExists(RoleConstants.ADMIN, RoleConstants.ADMIN_DESC);
    createRoleIfNotExists(RoleConstants.MANAGER, RoleConstants.MANAGER_DESC);
    createRoleIfNotExists(RoleConstants.STAFF, RoleConstants.STAFF_DESC);

    log.info("Default roles initialized successfully");
  }

  private void createRoleIfNotExists(String roleName, String description) {
    if (!roleRepository.existsByName(roleName)) {
      Role role = Role.builder().name(roleName).description(description).build();
      roleRepository.save(role);
      log.info("Created role: {}", roleName);
    }
  }

  private void initializeUsers() {
    Role userRole = roleRepository.findByName(RoleConstants.CUSTOMER).orElse(null);
    Role adminRole = roleRepository.findByName(RoleConstants.ADMIN).orElse(null);
    Role managerRole = roleRepository.findByName(RoleConstants.MANAGER).orElse(null);
    Role staffRole = roleRepository.findByName(RoleConstants.STAFF).orElse(null);

    createUserIfNotExists("customer@greenloop.com", "Customer123", userRole, "Customer");
    createUserIfNotExists("admin@greenloop.com", "Admin123", adminRole, "Admin");
    createUserIfNotExists("manager@greenloop.com", "Manager123", managerRole, "Manager");
    createUserIfNotExists("staff@greenloop.com", "Staff123", staffRole, "Staff");

    log.info("Default users initialized successfully");
  }

  private void createUserIfNotExists(String email, String password, Role role, String fullName) {
    if (!userRepository.existsByEmail(email)) {
      User user =
          User.builder()
              .email(email)
              .password(passwordEncoder.encode(password))
              .fullName(fullName)
              .roles(List.of(role))
              .isEmailVerified(true)
              .build();
      userRepository.save(user);
      log.info("Created user: {} with role: {}", email, role.getName());
    }
  }
}
