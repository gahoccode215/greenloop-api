package com.greenloop.order.service;

import com.greenloop.order.dto.request.*;
import com.greenloop.order.dto.response.PageResponseDTO;
import com.greenloop.order.dto.response.ReturnRequestResponse;
import com.greenloop.order.dto.response.ReturnShipmentInfoResponse;
import com.greenloop.order.goship.dto.CreateShipmentResponse;
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

    ReturnRequestResponse approveReturnRequest(Long returnRequestId, Long staffId,
                                               ApproveReturnRequestRequest request);

    ReturnRequestResponse rejectReturnRequest(Long returnRequestId, Long staffId,
                                              RejectReturnRequestRequest request);
    ReturnShipmentInfoResponse shipReturnRequest(Long returnRequestId, Long staffId,
                                                 CreateReturnShipmentRequest request);
    ReturnRequestResponse inspectAndApprove(Long returnRequestId, Long staffId,
                                            InspectReturnRequest request,
                                            List<MultipartFile> inspectionImages);

    ReturnRequestResponse inspectAndReject(Long returnRequestId, Long staffId,
                                           InspectReturnRequest request,
                                           List<MultipartFile> inspectionImages);

    ReturnRequestResponse completeRefund(Long returnRequestId, Long staffId,
                                         CompleteRefundRequest request,
                                         MultipartFile refundProofImage);


}
