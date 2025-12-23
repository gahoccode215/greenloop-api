package com.greenloop.order.controller.simulator;

import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.dto.simulator.ShipmentSimulatorResponse;
import com.greenloop.order.service.ShipmentSimulatorService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/simulator/shipments")
@RequiredArgsConstructor
@Slf4j
public class ShipmentSimulatorController {

    private final ShipmentSimulatorService simulatorService;

    @GetMapping
//    @PreAuthorize("hasAnyRole('ADMIN', 'STAFF', 'MANAGER')")
    public ResponseEntity<ApiResponseDTO<List<ShipmentSimulatorResponse>>> getActiveShipments() {
        List<ShipmentSimulatorResponse> shipments = simulatorService.getActiveShipments();
        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        String.format("Lấy danh sách %d vận đơn thành công", shipments.size()),
                        shipments,
                        HttpStatus.OK
                )
        );
    }
}
