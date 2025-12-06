package com.greenloop.order.service;

import com.greenloop.order.dto.request.CreateOrderOfflineRequest;
import com.greenloop.order.dto.response.OrderOfflineResponse;
import org.springframework.web.multipart.MultipartFile;

public interface OrderOfflineService {
    OrderOfflineResponse createOrderOffline(CreateOrderOfflineRequest request, MultipartFile paymentProofImage);
}
