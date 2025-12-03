package com.greenloop.order.service;

import com.greenloop.order.dto.request.CreateOrderOfflineRequest;
import com.greenloop.order.dto.response.OrderOfflineResponse;

public interface OrderOfflineService {
    OrderOfflineResponse createOrderOffline(CreateOrderOfflineRequest request);
}
