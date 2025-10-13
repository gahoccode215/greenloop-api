package com.greenloop.user.service;

import com.greenloop.user.dto.response.CustomerResponse;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface AdminCustomerService {
    Page<CustomerResponse> getCustomers(String search, String status, Pageable pageable);
}
