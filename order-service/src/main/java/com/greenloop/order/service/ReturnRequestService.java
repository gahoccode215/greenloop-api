package com.greenloop.order.service;

import com.greenloop.order.dto.request.CreateReturnRequestRequest;
import com.greenloop.order.dto.request.ReturnRequestFilterRequest;
import com.greenloop.order.dto.response.PageResponseDTO;
import com.greenloop.order.dto.response.ReturnRequestResponse;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

public interface ReturnRequestService {

    ReturnRequestResponse createReturnRequest(Long customerId, String orderId,
                                              CreateReturnRequestRequest request,
                                              List<MultipartFile> images);

    ReturnRequestResponse getReturnRequestById(Long returnRequestId);

    PageResponseDTO<ReturnRequestResponse> getReturnRequestsByOrder(
            String orderId, Integer page, Integer size, String sortBy, String sortDirection);

    PageResponseDTO<ReturnRequestResponse> getReturnRequestsByCustomer(
            Long customerId, Integer page, Integer size, String sortBy, String sortDirection);

    PageResponseDTO<ReturnRequestResponse> getAllReturnRequests(ReturnRequestFilterRequest filter);
}
