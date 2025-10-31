package com.greenloop.user.service;

import com.greenloop.user.dto.response.EmployeeResponse;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface AdminEmployeeService {
    Page<EmployeeResponse> getEmployees(String search, String status, Pageable pageable);
    EmployeeResponse getEmployeeDetail(Long id);
}
