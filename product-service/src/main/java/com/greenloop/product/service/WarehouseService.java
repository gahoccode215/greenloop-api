package com.greenloop.product.service;

import com.greenloop.product.dto.request.UpdateDonationItemStatusRequest;
import com.greenloop.product.dto.response.UpdateDonationItemStatusResponse;

public interface WarehouseService {
    UpdateDonationItemStatusResponse changeStatusDonationItems(UpdateDonationItemStatusRequest request);
}
