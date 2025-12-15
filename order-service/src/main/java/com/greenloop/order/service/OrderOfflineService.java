package com.greenloop.order.service;

import com.greenloop.order.dto.request.CreateOrderOfflineRequest;
import com.greenloop.order.dto.response.OrderOfflineResponse;
import com.greenloop.order.entity.Order;
import org.springframework.web.multipart.MultipartFile;

public interface OrderOfflineService {
    OrderOfflineResponse createOrderOffline(CreateOrderOfflineRequest request, MultipartFile paymentProofImage);
    void publishOrderOfflineCreatedEventDelayed(Order order);

}
