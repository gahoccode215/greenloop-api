package com.greenloop.order.goship.service.impl;

import com.greenloop.order.entity.Order;
import com.greenloop.order.entity.ShippingAddress;
import com.greenloop.order.goship.client.GoShipClient;
import com.greenloop.order.goship.dto.*;
import com.greenloop.order.goship.service.GoShipService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class GoShipServiceImpl implements GoShipService {

    private final GoShipClient goShipClient;


    @Override
    public List<RateResponse> calculateShippingRates(CalculateRateRequest request) {
        try {

            return goShipClient.calculateRates(request);

        } catch (Exception e) {
            throw new RuntimeException("Không thể tính cước phí vận chuyển: " + e.getMessage());
        }
    }





}
