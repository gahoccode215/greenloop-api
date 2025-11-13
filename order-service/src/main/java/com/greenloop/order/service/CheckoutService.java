package com.greenloop.order.service;

import com.greenloop.order.dto.request.CheckoutRequest;
import com.greenloop.order.dto.response.CheckoutResponse;

public interface CheckoutService {
    CheckoutResponse checkout(CheckoutRequest request);
}
