package com.greenloop.user.service;

import com.greenloop.user.dto.request.CreateEmployeeRequest;
import com.greenloop.user.dto.request.UpdateEmployeeRequest;
import com.greenloop.user.dto.response.CreateEmployeeResponse;
import com.greenloop.user.dto.response.EmployeeResponse;
import com.greenloop.user.dto.response.PageResponseDTO;
import org.springframework.data.domain.Pageable;
import org.springframework.web.multipart.MultipartFile;

public interface AdminEmployeeService {
    PageResponseDTO<EmployeeResponse> getEmployees(String search, String status, Pageable pageable);
    EmployeeResponse getEmployeeDetail(Long id);
    CreateEmployeeResponse createEmployee(CreateEmployeeRequest request, MultipartFile avatar);
    EmployeeResponse updateEmployee(Long id, UpdateEmployeeRequest request, MultipartFile avatar);
    EmployeeResponse changeEmployeeStatus(Long id, Boolean isActive);
}
