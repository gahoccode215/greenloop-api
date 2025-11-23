package com.greenloop.order.goship.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.greenloop.order.goship.dto.GoShipWebhookPayload;
import com.greenloop.order.goship.service.GoShipWebhookService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/webhooks/goship")
@RequiredArgsConstructor
@Slf4j
public class GoShipWebhookController {

    private final GoShipWebhookService webhookService;
    private final ObjectMapper objectMapper;

    @PostMapping
    public ResponseEntity<Void> handleGoShipWebhook(
            @RequestHeader(value = "x-goship-hmac-sha256", required = false) String hmacSignature,
            @RequestBody String rawPayload) {

        log.info("Received GoShip webhook request");
        log.debug("Raw payload: {}", rawPayload);

        try {
            // Parse payload
            GoShipWebhookPayload payload = objectMapper.readValue(rawPayload, GoShipWebhookPayload.class);

            log.info("Webhook payload - GCode: {}, Status: {}, OrderId: {}",
                    payload.getGcode(), payload.getStatus(), payload.getOrderId());

            // TODO: Verify HMAC signature in production
            // For now, skip HMAC verification for easier testing
            if (hmacSignature != null) {
                log.info("Received HMAC signature: {}", hmacSignature);
            }

            // Process webhook
            webhookService.handleWebhook(payload);

            // Always return 200 OK to GoShip
            return ResponseEntity.ok().build();

        } catch (Exception e) {
            log.error("Error processing GoShip webhook: {}", e.getMessage(), e);
            // Return 200 anyway to prevent GoShip from retrying
            return ResponseEntity.ok().build();
        }
    }
}
