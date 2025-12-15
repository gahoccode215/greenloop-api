package com.greenloop.order.service.impl;

import com.greenloop.order.dto.response.WarehouseSettingResponse;
import com.greenloop.order.entity.WarehouseSetting;
import com.greenloop.order.repository.WarehouseSettingRepository;
import com.greenloop.order.service.WarehouseSettingService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class WarehouseSettingServiceImpl implements WarehouseSettingService {

    private final WarehouseSettingRepository repository;

    /**
     * Lấy entity kho (dùng nội bộ)
     */
    @Override
    public WarehouseSetting getWarehouse() {
        return repository.findAll().stream()
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Chưa có thông tin kho"));
    }

    /**
     * Lấy DTO kho (dùng cho API response)
     */
    @Override
    public WarehouseSettingResponse getWarehouseResponse() {
        WarehouseSetting warehouse = getWarehouse();
        return mapToResponse(warehouse);
    }

    /**
     * Cập nhật thông tin kho
     */
    @Override
    @Transactional
    public WarehouseSettingResponse updateWarehouse(WarehouseSetting setting) {
        WarehouseSetting existing = getWarehouse();

        existing.setName(setting.getName());
        existing.setPhone(setting.getPhone());
        existing.setAddress(setting.getAddress());
        existing.setWardCode(setting.getWardCode());
        existing.setWardName(setting.getWardName());
        existing.setDistrictId(setting.getDistrictId());
        existing.setDistrictName(setting.getDistrictName());
        existing.setCityId(setting.getCityId());
        existing.setCityName(setting.getCityName());

        WarehouseSetting updated = repository.save(existing);
        log.info("Đã cập nhật thông tin kho: {}", updated.getName());

        return mapToResponse(updated);
    }


    private WarehouseSettingResponse mapToResponse(WarehouseSetting warehouse) {
        return WarehouseSettingResponse.builder()
                .id(warehouse.getId())
                .name(warehouse.getName())
                .phone(warehouse.getPhone())
                .address(warehouse.getAddress())
                .wardCode(warehouse.getWardCode())
                .wardName(warehouse.getWardName())
                .districtId(warehouse.getDistrictId())
                .districtName(warehouse.getDistrictName())
                .cityId(warehouse.getCityId())
                .cityName(warehouse.getCityName())
                .createdAt(warehouse.getCreatedAt())
                .updatedAt(warehouse.getUpdatedAt())
                .build();
    }
}
