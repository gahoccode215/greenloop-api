package com.greenloop.order.query.controller;

import com.greenloop.order.dto.OrderDTO;
import com.greenloop.order.query.GetOrderQuery;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.axonframework.messaging.responsetypes.ResponseTypes;
import org.axonframework.queryhandling.QueryGateway;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/orders")
@RequiredArgsConstructor
@Tag(name = "Order Query Controller", description = "Order Query Controller")
@Slf4j
public class OrderQueryController {

    private final QueryGateway queryGateway;

    @GetMapping("/{orderId}")
    public ResponseEntity<OrderDTO> getOrder(@PathVariable String orderId) {
        GetOrderQuery
                query = new GetOrderQuery(orderId);
        OrderDTO orderDTO = queryGateway.query(query, ResponseTypes.instanceOf(OrderDTO.class))
                .join();
        return ResponseEntity.ok(orderDTO);
    }
}

