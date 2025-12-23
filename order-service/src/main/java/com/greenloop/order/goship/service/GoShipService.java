package com.greenloop.order.goship.service;

import com.greenloop.order.dto.request.CreateShipmentRequestDTO;
import com.greenloop.order.goship.dto.*;

import java.util.List;

public interface GoShipService {

    List<RateResponse> calculateShippingRates(CalculateRateRequest request);

    CreateShipmentResponse createShipmentForOrder(String orderId, CreateShipmentRequestDTO staffRequest);

    CreateShipmentResponse createReturnShipment(Long returnRequestId, CreateShipmentRequestDTO staffRequest);
}
