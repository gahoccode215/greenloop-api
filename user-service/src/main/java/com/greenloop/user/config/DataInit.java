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

    // Customers
  createUserIfNotExists("customer@greenloop.com", "Customer123", userRole, "Customer");
  createUserIfNotExists("customer1@greenloop.com", "Customer123", userRole, "Customer1");  // ✅ FIX
  createUserIfNotExists("customer2@greenloop.com", "Customer123", userRole, "Customer2");  // ✅ FIX
  createUserIfNotExists("customer3@greenloop.com", "Customer123", userRole, "Customer3");  // ✅ FIX
  createUserIfNotExists("customer4@greenloop.com", "Customer123", userRole, "Customer4");  // ✅ FIX
  createUserIfNotExists("customer5@greenloop.com", "Customer123", userRole, "Customer5");  // ✅ FIX
  createUserIfNotExists("customer6@greenloop.com", "Customer123", userRole, "Customer6");  // ✅ FIX

  // Admins
  createUserIfNotExists("admin@greenloop.com", "Admin123", adminRole, "Admin");
  createUserIfNotExists("admin1@greenloop.com", "Admin123", adminRole, "Admin1");  // ✅ FIX
  createUserIfNotExists("admin2@greenloop.com", "Admin123", adminRole, "Admin2");  // 

    // Managers
  createUserIfNotExists("manager@greenloop.com", "Manager123", managerRole, "Manager");
  createUserIfNotExists("manager1@greenloop.com", "Manager123", managerRole, "Manager1");  // ✅ FIX
  createUserIfNotExists("manager2@greenloop.com", "Manager123", managerRole, "Manager2");  // ✅ FIX
  createUserIfNotExists("manager3@greenloop.com", "Manager123", managerRole, "Manager3");  // ✅ FIX
  createUserIfNotExists("manager4@greenloop.com", "Manager123", managerRole, "Manager4");  // ✅ FIX

   // Store Managers
  createUserIfNotExists("store_manager1@greenloop.com", "StoreManager123", storeManagerRole, "Store Manager1");  // ✅ FIX (typo + space)
  createUserIfNotExists("store_manager2@greenloop.com", "StoreManager123", storeManagerRole, "Store Manager2");  // ✅ FIX
  createUserIfNotExists("store_manager3@greenloop.com", "StoreManager123", storeManagerRole, "Store Manager3");  // ✅ FIX
  createUserIfNotExists("store_manager4@greenloop.com", "StoreManager123", storeManagerRole, "Store Manager4");  // ✅ FIX
  createUserIfNotExists("store_manager5@greenloop.com", "StoreManager123", storeManagerRole, "Store Manager5");  // ✅ FIX

    createUserIfNotExists("staff@greenloop.com", "Staff123", staffRole, "Staff");
  createUserIfNotExists("staff1@greenloop.com", "Staff123", staffRole, "Staff1");  
  createUserIfNotExists("staff2@greenloop.com", "Staff123", staffRole, "Staff2");
  createUserIfNotExists("staff3@greenloop.com", "Staff123", staffRole, "Staff3"); 
  createUserIfNotExists("staff4@greenloop.com", "Staff123", staffRole, "Staff4"); 
  createUserIfNotExists("staff5@greenloop.com", "Staff123", staffRole, "Staff5");  
  createUserIfNotExists("staff6@greenloop.com", "Staff123", staffRole, "Staff6"); 
  createUserIfNotExists("staff7@greenloop.com", "Staff123", staffRole, "Staff7");  
  createUserIfNotExists("staff8@greenloop.com", "Staff123", staffRole, "Staff8");  
  createUserIfNotExists("staff9@greenloop.com", "Staff123", staffRole, "Staff9");  

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
