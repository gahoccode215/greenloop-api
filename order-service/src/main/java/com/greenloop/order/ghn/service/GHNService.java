package com.greenloop.order.ghn.service;


import com.greenloop.order.ghn.dto.request.CreateShippingRequest;
import com.greenloop.order.ghn.dto.response.*;

import java.util.List;

public interface GHNService {
    ShippingOrderResponse createShippingOrder(String orderId, CreateShippingRequest createShippingRequest);
    List<ProvinceResponse> getProvinces();
    List<DistrictResponse> getDistricts(Integer provinceId);
    List<WardResponse> getWards(Integer districtId);

    CancelOrderResponse cancelOrder(String orderId);

    String trackOrder(String ghnOrderCode);
}
