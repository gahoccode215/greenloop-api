package com.greenloop.user.service.impl;

import com.greenloop.user.constant.RoleConstants;
import com.greenloop.user.dto.response.EmployeeResponse;
import com.greenloop.user.dto.response.PageResponseDTO;
import com.greenloop.user.entity.Role;
import com.greenloop.user.entity.User;
import com.greenloop.user.exception.EmployeeNotFoundException;
import com.greenloop.user.repository.UserRepository;
import com.greenloop.user.service.AdminEmployeeService;
import com.greenloop.user.util.PageResponseUtil;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.Predicate;
import java.util.ArrayList;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AdminEmployeeServiceImpl implements AdminEmployeeService {

    private final UserRepository userRepository;

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
