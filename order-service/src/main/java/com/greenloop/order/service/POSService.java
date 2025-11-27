package com.greenloop.order.service;

import com.greenloop.order.dto.request.order.offline.POSCheckoutRequest;
import com.greenloop.order.dto.response.order.offline.POSCheckoutResponse;

public interface POSService {

    POSCheckoutResponse checkout(POSCheckoutRequest request);
}
