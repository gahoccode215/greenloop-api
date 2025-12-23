package com.greenloop.order.service;

import com.greenloop.order.dto.ParcelDimensionDTO;
import com.greenloop.order.dto.response.ShippingEstimateResponse;
import com.greenloop.order.entity.CartItem;

import java.math.BigDecimal;
import java.util.List;

public interface ShippingCalculationService {

    ShippingEstimateResponse calculateShippingFee(
            List<CartItem> cartItems,
            BigDecimal productTotal,
            String cityCode,
            String districtCode);

    ParcelDimensionDTO calculateParcelDimensions(List<CartItem> cartItems);
}
