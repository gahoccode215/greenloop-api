package com.greenloop.user.service;

import com.greenloop.user.dto.request.UpdateCustomerRequest;
import com.greenloop.user.dto.response.CustomerResponse;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface AdminCustomerService {
    Page<CustomerResponse> getCustomers(String search, String status, Pageable pageable);
    CustomerResponse getCustomerDetail(Long id);
    CustomerResponse updateCustomer(Long id, UpdateCustomerRequest request);
    CustomerResponse updateCustomerStatus(Long id, Boolean isActive);


}
