package com.greenloop.order.repository;

import com.greenloop.order.entity.WarehouseSetting;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

public interface WarehouseSettingRepository extends JpaRepository<WarehouseSetting, Long> {
}
