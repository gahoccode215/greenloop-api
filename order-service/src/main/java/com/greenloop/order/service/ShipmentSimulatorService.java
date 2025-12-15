package com.greenloop.order.service;

import com.greenloop.order.dto.simulator.ShipmentSimulatorResponse;

import java.util.List;


public interface ShipmentSimulatorService {

    /**
     * Lấy danh sách vận đơn đang active (READY_TO_SHIP → RETURNING)
     * @return Danh sách vận đơn
     */
    List<ShipmentSimulatorResponse> getActiveShipments();
}
