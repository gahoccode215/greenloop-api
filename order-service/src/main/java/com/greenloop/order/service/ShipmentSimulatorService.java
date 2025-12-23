package com.greenloop.order.service;

import com.greenloop.order.dto.simulator.ShipmentSimulatorResponse;

import java.util.List;


public interface ShipmentSimulatorService {

    List<ShipmentSimulatorResponse> getActiveShipments();
}
