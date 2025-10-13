package com.greenloop.user.service.impl;

import com.greenloop.user.constant.RoleConstants;
import com.greenloop.user.dto.request.UpdateCustomerRequest;
import com.greenloop.user.dto.response.CustomerResponse;
import com.greenloop.user.entity.User;
import com.greenloop.user.exception.CustomerNotFoundException;
import com.greenloop.user.repository.UserRepository;
import com.greenloop.user.service.AdminCustomerService;
import jakarta.ws.rs.NotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import jakarta.persistence.criteria.Predicate;
import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AdminCustomerServiceImpl implements AdminCustomerService {

    private final UserRepository userRepository;

    @Override
    public Page<CustomerResponse> getCustomers(String search, String status, Pageable pageable) {
        Specification<User> spec = (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            predicates.add(cb.equal(root.get("role").get("name"), "CUSTOMER"));

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

        return userRepository.findAll(spec, pageable).map(this::mapUserToCustomerResponse);
    }

    @Override
    public CustomerResponse getCustomerDetail(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(CustomerNotFoundException::new);
        if (!RoleConstants.CUSTOMER.equals(user.getRole().getName())) {
            throw new CustomerNotFoundException();
        }
        return mapUserToCustomerResponse(user);
    }

    @Override
    public CustomerResponse updateCustomer(Long id, UpdateCustomerRequest req) {
        User user = userRepository.findById(id)
                .orElseThrow(CustomerNotFoundException::new);
        if (!RoleConstants.CUSTOMER.equals(user.getRole().getName())) {
            throw new CustomerNotFoundException();
        }
        user.setFirstName(req.getFirstName());
        user.setLastName(req.getLastName());
        user.setPhoneNumber(req.getPhoneNumber());
        user.setAvatarUrl(req.getAvatarUrl());
        user.setDateOfBirth(req.getDateOfBirth());
        userRepository.save(user);
        return mapUserToCustomerResponse(user);
    }


    private CustomerResponse mapUserToCustomerResponse(User user) {
        return CustomerResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .phoneNumber(user.getPhoneNumber())
                .avatarUrl(user.getAvatarUrl())
                .dateOfBirth(user.getDateOfBirth())
                .department(user.getDepartment())
                .isActive(user.getIsActive())
                .isEmailVerified(user.getIsEmailVerified())
                .createdAt(user.getCreatedAt())
                .updatedAt(user.getUpdatedAt())
                .build();
    }
}
