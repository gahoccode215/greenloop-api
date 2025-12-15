package com.greenloop.order.config;

import com.greenloop.order.entity.WarehouseSetting;
import com.greenloop.order.repository.WarehouseSettingRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class WarehouseDataSeeder implements CommandLineRunner {

    private final WarehouseSettingRepository repository;

    @Override
    public void run(String... args) {
        if (repository.count() == 0) {
            WarehouseSetting warehouse = WarehouseSetting.builder()
                    .name("GreenLoop Warehouse")
                    .phone("0987654321")
                    .address("39 Bến Nghé")
                    .wardCode(8955L)
                    .wardName("Phường Bến Nghé")
                    .districtId(700100)
                    .districtName("Quận 1")
                    .cityId(700000)
                    .cityName("Hồ Chí Minh")
                    .build();

            repository.save(warehouse);
        }

    }
}
