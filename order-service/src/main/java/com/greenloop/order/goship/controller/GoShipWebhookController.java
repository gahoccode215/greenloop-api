package com.greenloop.order.goship.controller;

import com.greenloop.order.dto.response.ApiResponseDTO;
import com.greenloop.order.goship.dto.GoShipWebhookPayload;
import com.greenloop.order.goship.service.GoShipWebhookService;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/goship/webhooks")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "GoShip Webhook", description = "GoShip Webhook APIs")
public class GoShipWebhookController {

    private final GoShipWebhookService webhookService;


    @PostMapping
    public ResponseEntity<ApiResponseDTO<String>> handleGoShipWebhook(
            @RequestBody GoShipWebhookPayload payload) {
        webhookService.handleWebhook(payload);
        return ResponseEntity.ok(
                ApiResponseDTO.success(
                        "Webhook processed successfully",
                        "Order " + payload.getOrderId() + " updated to status: " + payload.getStatusText(),
                        HttpStatus.OK
                )
        );

    }

}
