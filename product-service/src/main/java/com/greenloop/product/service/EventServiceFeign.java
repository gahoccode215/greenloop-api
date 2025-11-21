package com.greenloop.product.service;

import com.greenloop.product.dto.response.EventResponse;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "event-service")
public interface EventServiceFeign {

    @GetMapping(value = "/api/v1/events/internal/{eventId}/staff/{staffId}/validate", headers = "API_SECRET_HEADER=greenloopsecret")
    Boolean validateStaffInEvent(@PathVariable("eventId") Long eventId, @PathVariable("staffId") Long staffId);

    @GetMapping(value = "/api/v1/events/internal/{eventId}/info", headers = "API_SECRET_HEADER=greenloopsecret")
    EventResponse getInfoEventId(@PathVariable("eventId") Long eventId);
}

