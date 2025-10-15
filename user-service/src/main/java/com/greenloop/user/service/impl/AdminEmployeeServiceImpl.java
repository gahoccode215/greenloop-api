package com.greenloop.user.service.impl;

import com.greenloop.user.constant.RoleConstants;
import com.greenloop.user.dto.request.CreateEmployeeRequest;
import com.greenloop.user.dto.request.UpdateEmployeeRequest;
import com.greenloop.user.dto.response.EmployeeResponse;
import com.greenloop.user.entity.Role;
import com.greenloop.user.entity.User;
import com.greenloop.user.exception.EmailAlreadyExistsException;
import com.greenloop.user.exception.RoleNotFoundException;
import com.greenloop.user.exception.UserNotFoundException;
import com.greenloop.user.repository.RoleRepository;
import com.greenloop.user.repository.UserRepository;
import com.greenloop.user.service.AdminEmployeeService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import jakarta.persistence.criteria.Predicate;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminEmployeeServiceImpl implements AdminEmployeeService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;

    @Override
    public Page<EmployeeResponse> getEmployees(String search, String status, Pageable pageable) {
        Specification<User> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            predicates.add(
                    cb.or(
                            cb.equal(root.get("role").get("name"), "MANAGER"),
                            cb.equal(root.get("role").get("name"), "STAFF")
                    )
            );
            if (search != null && !search.isEmpty()) {
                String searchPattern = "%" + search.toLowerCase() + "%";
                predicates.add(cb.or(
                        cb.like(cb.lower(root.get("email")), searchPattern),
                        cb.like(cb.lower(root.get("firstName")), searchPattern),
                        cb.like(cb.lower(root.get("lastName")), searchPattern),
                        cb.like(cb.lower(root.get("phoneNumber")), searchPattern)
                ));
            }
            if (status != null && !status.isEmpty()) {
                predicates.add(cb.equal(root.get("isActive"), Boolean.valueOf(status)));
            }
            return cb.and(predicates.toArray(new Predicate[0]));
        };
        return userRepository.findAll(spec, pageable).map(this::userToEmployeeResponse);
    }

    @Override
    @Transactional
    public EmployeeResponse createEmployee(CreateEmployeeRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException();
        }
        Role role = roleRepository.findByName(request.getRole())
                .orElseThrow(() -> new RoleNotFoundException(request.getRole()));

        if (!role.getName().equals(RoleConstants.MANAGER) && !role.getName().equals(RoleConstants.STAFF)) {
            throw new RoleNotFoundException(request.getRole());
        }

        User user = User.builder()
                .email(request.getEmail())
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .phoneNumber(request.getPhoneNumber())
                .department(request.getDepartment())
                .role(role)
                .password(passwordEncoder.encode(generateDefaultPassword()))
                .isActive(true)
                .build();

        User savedUser = userRepository.save(user);

        return userToEmployeeResponse(savedUser);
    }

    @Override
    public EmployeeResponse getEmployeeById(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException(id));

        String roleName = user.getRole().getName();
        if (!roleName.equals(RoleConstants.MANAGER) && !roleName.equals(RoleConstants.STAFF)) {
            throw new UserNotFoundException(id);
        }

        return userToEmployeeResponse(user);
    }

    @Override
    @Transactional
    public EmployeeResponse updateEmployee(Long id, UpdateEmployeeRequest request) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException(id));

        String currentRole = user.getRole().getName();
        if (!currentRole.equals(RoleConstants.MANAGER) && !currentRole.equals(RoleConstants.STAFF)) {
            throw new UserNotFoundException(id);
        }


        if (request.getPhoneNumber() != null && !request.getPhoneNumber().equals(user.getPhoneNumber())) {
            user.setPhoneNumber(request.getPhoneNumber());
        }

        if (request.getFirstName() != null) {
            user.setFirstName(request.getFirstName());
        }

        if (request.getLastName() != null) {
            user.setLastName(request.getLastName());
        }

        if (request.getDepartment() != null) {
            user.setDepartment(request.getDepartment());
        }

        if (request.getRoleName() != null) {
            Role role = roleRepository.findByName(request.getRoleName())
                    .orElseThrow(() -> new RoleNotFoundException(request.getRoleName()));

            if (!role.getName().equals(RoleConstants.MANAGER) && !role.getName().equals(RoleConstants.STAFF)) {
                throw new RoleNotFoundException(request.getRoleName());
            }
            user.setRole(role);
        }

        if (request.getIsActive() != null) {
            user.setIsActive(request.getIsActive());
        }

        User updatedUser = userRepository.save(user);

        return userToEmployeeResponse(updatedUser);
    }



    private String generateDefaultPassword() {
        return "TempPass@" + System.currentTimeMillis();
    }

    private EmployeeResponse userToEmployeeResponse(User user) {
        return EmployeeResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .phoneNumber(user.getPhoneNumber())
                .department(user.getDepartment())
                .isActive(user.getIsActive())
                .createdAt(user.getCreatedAt())
                .build();
    }
}
