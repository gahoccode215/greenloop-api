package com.greenloop.user.service;

import com.greenloop.user.dto.request.CreateEmployeeRequest;
import com.greenloop.user.dto.response.CreateEmployeeResponse;
import com.greenloop.user.dto.response.EmployeeResponse;
import com.greenloop.user.dto.response.PageResponseDTO;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

public interface AdminEmployeeService {
    PageResponseDTO<EmployeeResponse> getEmployees(String search, String status, Pageable pageable);
    EmployeeResponse getEmployeeDetail(Long id);
    CreateEmployeeResponse createEmployee(CreateEmployeeRequest request);
}
