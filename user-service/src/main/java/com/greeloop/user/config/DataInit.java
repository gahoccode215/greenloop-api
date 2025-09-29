package com.greeloop.user.config;

import com.greeloop.user.constant.RoleConstants;
import com.greeloop.user.entity.Role;
import com.greeloop.user.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class DataInit implements CommandLineRunner {
    private final RoleRepository roleRepository;

    @Override
    public void run(String... args) throws Exception {
        initializeRoles();
    }

    private void initializeRoles() {
        createRoleIfNotExists(RoleConstants.USER, RoleConstants.USER_DESC);
        createRoleIfNotExists(RoleConstants.ADMIN, RoleConstants.ADMIN_DESC);

        log.info("Default roles initialized successfully");
    }

    private void createRoleIfNotExists(String roleName, String description) {
        if (!roleRepository.existsByName(roleName)) {
            Role role = Role.builder()
                    .name(roleName)
                    .description(description)
                    .build();
            roleRepository.save(role);
            log.info("Created role: {}", roleName);
        }
    }

}
