package com.greenloop.order.service;

import com.greenloop.order.dto.response.OrderHistoryResponse;
import java.util.List;


public interface OrderHistoryService {


    List<OrderHistoryResponse> getOrderHistory(String orderId);
}
