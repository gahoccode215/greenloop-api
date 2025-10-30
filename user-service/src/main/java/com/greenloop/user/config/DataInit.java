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
    createRoleIfNotExists(RoleConstants.STORE_MANAGER, RoleConstants.STORE_MANAGER_DESC);

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
    Role storeManagerRole = roleRepository.findByName(RoleConstants.STORE_MANAGER).orElse(null);

    createUserIfNotExists("customer1@greeloop.com", "Customer123", userRole, "Customer1");
    createUserIfNotExists("customer2@greeloop.com", "Customer123", userRole, "Customer2");
    createUserIfNotExists("customer3@greeloop.com", "Customer123", userRole, "Customer3");
    createUserIfNotExists("customer4@greeloop.com", "Customer123", userRole, "Customer4");
    createUserIfNotExists("customer5@greeloop.com", "Customer123", userRole, "Customer5");
    createUserIfNotExists("customer6@greeloop.com", "Customer123", userRole, "Customer6");

    createUserIfNotExists("admin1@greeloop.com", "Admin123", adminRole, "Admin1");
    createUserIfNotExists("admin2@greeloop.com", "Admin123", adminRole, "Admin2");

    createUserIfNotExists("manager1@greeloop.com", "Manager123", managerRole, "Manager1");
    createUserIfNotExists("manager2@greeloop.com", "Manager123", managerRole, "Manager2");
    createUserIfNotExists("manager3@greeloop.com", "Manager123", managerRole, "Manager3");
    createUserIfNotExists("manager4@greeloop.com", "Manager123", managerRole, "Manager4");

    createUserIfNotExists(
        "store_manager1@greenloop", " StoreManager123", storeManagerRole, "Store Manager1");
    createUserIfNotExists(
        "store_manager2@greenloop", " StoreManager123", storeManagerRole, "Store Manager2");
    createUserIfNotExists(
        "store_manager3@greenloop", " StoreManager123", storeManagerRole, "Store Manager3");
    createUserIfNotExists(
        "store_manager4@greenloop", " StoreManager123", storeManagerRole, "Store Manager4");
    createUserIfNotExists(
        "store_manager5@greenloop", " StoreManager123", storeManagerRole, "Store Manager5");

    createUserIfNotExists("staff1@greeloop.com", "Staff123", staffRole, "Staff1");
    createUserIfNotExists("staff2@greeloop.com", "Staff123", staffRole, "Staff2");
    createUserIfNotExists("staff3@greeloop.com", "Staff123", staffRole, "Staff3");
    createUserIfNotExists("staff4@greeloop.com", "Staff123", staffRole, "Staff4");
    createUserIfNotExists("staff5@greeloop.com", "Staff123", staffRole, "Staff5");
    createUserIfNotExists("staff6@greeloop.com", "Staff123", staffRole, "Staff6");
    createUserIfNotExists("staff7@greeloop.com", "Staff123", staffRole, "Staff7");
    createUserIfNotExists("staff8@greeloop.com", "Staff123", staffRole, "Staff8");
    createUserIfNotExists("staff9@greeloop.com", "Staff123", staffRole, "Staff9");

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
