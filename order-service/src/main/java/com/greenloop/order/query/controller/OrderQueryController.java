package com.greenloop.order.query.controller;

import com.greenloop.order.query.GetOrderQuery;
import lombok.RequiredArgsConstructor;
import org.axonframework.queryhandling.QueryGateway;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/orders")
@RequiredArgsConstructor
public class OrderQueryController {

    private final QueryGateway queryGateway;

    @GetMapping("/{orderId}")
    public ResponseEntity<OrderDTO> getOrder(@PathVariable String orderId) {
        GetOrderQuery
                query = new GetOrderQuery(orderId);
        OrderDTO orderDTO = queryGateway.query(query, ResponseTypes.instanceOf(OrderDTO.class))
                .join();  // Blocking call
        return ResponseEntity.ok(orderDTO);
    }
}

