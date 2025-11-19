package com.greenloop.order.goship.service;

import com.greenloop.order.goship.dto.*;
import com.greenloop.order.entity.Order;

import java.util.List;

public interface GoShipService {


    List<RateResponse> calculateShippingRates(CalculateRateRequest request);


}
