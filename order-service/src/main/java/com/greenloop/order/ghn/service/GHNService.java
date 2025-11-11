package com.greenloop.order.ghn.service;


import com.greenloop.order.ghn.dto.request.CreateShippingRequest;
import com.greenloop.order.ghn.dto.response.DistrictResponse;
import com.greenloop.order.ghn.dto.response.ProvinceResponse;
import com.greenloop.order.ghn.dto.response.ShippingOrderResponse;
import com.greenloop.order.ghn.dto.response.WardResponse;

import java.util.List;

public interface GHNService {
    ShippingOrderResponse createShippingOrder(String orderId, CreateShippingRequest createShippingRequest);
    List<ProvinceResponse> getProvinces();
    List<DistrictResponse> getDistricts(Integer provinceId);
    List<WardResponse> getWards(Integer districtId);

    String trackOrder(String ghnOrderCode);
    void cancelOrder(String ghnOrderCode);
}
