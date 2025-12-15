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

/**
 * Shipper Simulator Controller
 *
 */
@RestController
@RequestMapping("/api/v1/simulator/shipments")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Shipment Simulator", description = "Shipper simulator APIs for sandbox testing (SANDBOX ONLY)")
public class ShipmentSimulatorController {

    private final ShipmentSimulatorService simulatorService;

    /**
     * Lấy danh sách vận đơn đang active
     * GET /api/simulator/shipments
     */
    @GetMapping
//    @PreAuthorize("hasAnyRole('ADMIN', 'STAFF', 'MANAGER')")
    @Operation(
            summary = "Get active shipments for simulator",
            description = """
            Lấy danh sách vận đơn đang trong quá trình vận chuyển để giả lập shipper.
            
            Bao gồm các đơn hàng có trạng thái:
            - READY_TO_SHIP: Chờ lấy hàng
            - SHIPPING: Đã lấy hàng
            - DELIVERING: Đang giao hàng
            - DELIVERED: Đã giao hàng (chờ staff complete)
            - DELIVERY_FAILED: Giao thất bại
            - RETURNING: Đang hoàn hàng
            
            API này CHỈ HOẠT ĐỘNG TRONG SANDBOX ENVIRONMENT (app.simulator.enabled=true)
            """
    )
    public ResponseEntity<ApiResponseDTO<List<ShipmentSimulatorResponse>>> getActiveShipments() {
        log.info("Shipper simulator: Fetching active shipments");

        List<ShipmentSimulatorResponse> shipments = simulatorService.getActiveShipments();

        log.info("Shipper simulator: Found {} active shipments", shipments.size());

        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        String.format("Lấy danh sách %d vận đơn thành công", shipments.size()),
                        shipments,
                        HttpStatus.OK
                )
        );
    }
}
