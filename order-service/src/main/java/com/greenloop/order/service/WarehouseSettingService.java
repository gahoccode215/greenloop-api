package com.greenloop.order.service;

import com.greenloop.order.dto.response.WarehouseSettingResponse;
import com.greenloop.order.entity.WarehouseSetting;

public interface WarehouseSettingService {
    WarehouseSetting getWarehouse();
    WarehouseSettingResponse getWarehouseResponse();
    WarehouseSettingResponse updateWarehouse(WarehouseSetting setting);
}
