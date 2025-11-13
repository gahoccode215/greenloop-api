package com.greenloop.user.service;

import com.greenloop.user.dto.request.UpdateCustomerRequest;
import com.greenloop.user.dto.response.CustomerResponse;
import com.greenloop.user.dto.response.PageResponseDTO;
import org.springframework.data.domain.Pageable;

public interface AdminCustomerService {
  PageResponseDTO<CustomerResponse> getCustomers(String search, String status, Pageable pageable);

  CustomerResponse getCustomerDetail(Long id);
    CustomerResponse changeCustomerStatus(Long id, Boolean isActive);
    CustomerResponse updateCustomer(Long id, UpdateCustomerRequest
            request);
}
