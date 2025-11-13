package com.greenloop.user.service.impl;

import com.greenloop.user.constant.RoleConstants;
import com.greenloop.user.dto.request.UpdateCustomerRequest;
import com.greenloop.user.dto.response.CustomerResponse;
import com.greenloop.user.dto.response.PageResponseDTO;
import com.greenloop.user.entity.Role;
import com.greenloop.user.entity.User;
import com.greenloop.user.exception.CustomerNotFoundException;
import com.greenloop.user.exception.EmailAlreadyExistsException;
import com.greenloop.user.exception.PhoneNumberAlreadyExistsException;
import com.greenloop.user.exception.UserNotFoundException;
import com.greenloop.user.repository.UserRepository;
import com.greenloop.user.service.AdminCustomerService;
import com.greenloop.user.util.PageResponseUtil;
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
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AdminCustomerServiceImpl implements AdminCustomerService {

  private final UserRepository userRepository;

  @Override
  //  @Cacheable(value = "customers_list", key = "#pageable.pageNumber + '-' + #search + '-' +
  // #status")
  public PageResponseDTO<CustomerResponse> getCustomers(
      String search, String status, Pageable pageable) {

    log.info("Getting customers - search: {}, status: {}", search, status);

    Specification<User> spec =
        (root, query, cb) -> {
          List<Predicate> predicates = new ArrayList<>();

          Join<Object, Object> roleJoin = root.join("roles");
          predicates.add(roleJoin.get("name").in(RoleConstants.CUSTOMER));

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

    Page<User> page = userRepository.findAll(spec, pageable);

    Page<CustomerResponse> customerPage = page.map(this::mapUserToCustomerResponse);

    PageResponseDTO<CustomerResponse> response = PageResponseUtil.toPageResponse(customerPage);

    log.info(
        "Retrieved {} customers out of {} total",
        response.getContent().size(),
        response.getTotalElements());

    return response;
  }

  @Override
  //  @Cacheable(value = "customer_detail", key = "#id")
  public CustomerResponse getCustomerDetail(Long id) {
    log.info("Getting customer detail for id: {}", id);

    User user =
        userRepository
            .findById(id)
            .orElseThrow(() -> new CustomerNotFoundException("Không tìm thấy khách hàng"));

    List<String> userRoles = user.getRoles().stream().map(Role::getName).toList();

    if (!userRoles.contains(RoleConstants.CUSTOMER)) {
      throw new CustomerNotFoundException("Người dùng không phải khách hàng");
    }

    return mapUserToCustomerResponse(user);
  }

    @Override
    @Transactional
//  @CacheEvict(
//      value = {"customer_detail", "customers_list"},
//      allEntries = true)
    public CustomerResponse changeCustomerStatus(Long id, Boolean isActive) {
        log.info("Changing customer status for id: {} to: {}", id, isActive);

        User customer =
                userRepository
                        .findById(id)
                        .orElseThrow(() -> new CustomerNotFoundException("Không tìm thấy khách hàng"));

        List<String> userRoles = customer.getRoles().stream().map(Role::getName).toList();

        if (!userRoles.contains(RoleConstants.CUSTOMER)) {
            throw new CustomerNotFoundException("Người dùng không phải khách hàng");
        }

        if (customer.isActive() == isActive) {
            log.info("Customer status is already {}, no change needed", isActive);
            return mapUserToCustomerResponse(customer);
        }

        customer.setActive(isActive);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String currentUserId = auth.getPrincipal().toString();
        customer.setUpdatedBy(Long.parseLong(currentUserId));

        User updatedCustomer = userRepository.save(customer);

        log.info(
                "Customer status changed successfully for id: {}. New status: {}",
                id,
                isActive ? "ACTIVE" : "INACTIVE");

        return mapUserToCustomerResponse(updatedCustomer);
    }

    @Override
    @Transactional
    public CustomerResponse updateCustomer(Long id, UpdateCustomerRequest request) {
        User customer = userRepository.findById(id)
                .orElseThrow(() -> new UserNotFoundException(id));

        if (request.getFullName() != null && !request.getFullName().isBlank()) {
            customer.setFullName(request.getFullName());
        }

        if (request.getEmail() != null && !request.getEmail().equals(customer.getEmail())) {
            if (userRepository.existsByEmail(request.getEmail())) {
                throw new EmailAlreadyExistsException();
            }
            customer.setEmail(request.getEmail());
        }

        if (request.getPhoneNumber() != null && !request.getPhoneNumber().equals(customer.getPhone())) {
            if (userRepository.existsByPhone(request.getPhoneNumber())) {
                throw new PhoneNumberAlreadyExistsException(request.getPhoneNumber());
            }
            customer.setPhone(request.getPhoneNumber());
        }

        if (request.getDateOfBirth() != null) {
            customer.setDateOfBirth(request.getDateOfBirth());
        }

        if (request.getGender() != null) {
            customer.setGender(request.getGender());
        }

        User savedCustomer = userRepository.save(customer);

        return mapUserToCustomerResponse(savedCustomer);
    }


    private CustomerResponse mapUserToCustomerResponse(User user) {
    return CustomerResponse.builder()
        .id(user.getId())
        .email(user.getEmail())
        .fullName(user.getFullName())
        .phoneNumber(user.getPhone())
        .dateOfBirth(user.getDateOfBirth())
        .gender(user.getGender())
        .avatarUrl(user.getAvatarUrl())
        .isActive(user.isActive())
        .isEmailVerified(user.getIsEmailVerified())
        .createdAt(user.getCreatedAt())
        .updatedAt(user.getUpdatedAt())
        .build();
  }
}
