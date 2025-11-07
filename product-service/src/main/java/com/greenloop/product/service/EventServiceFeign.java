package com.greenloop.product.service;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@FeignClient(name = "event-service")
public interface EventServiceFeign {

    @GetMapping(value = "/api/v1/events/{eventId}/staff/{staffId}/validate", headers = "API_SECRET_HEADER=greenloopsecret")
    Boolean validateStaffInEvent(@PathVariable("eventId") Long eventId, @PathVariable("staffId") Long staffId);
}

