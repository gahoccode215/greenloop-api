package com.greenloop.order.query.handler;

import com.greenloop.order.dto.OrderDTO;
import com.greenloop.order.query.GetOrderQuery;
import com.greenloop.order.service.OrderService;
import lombok.RequiredArgsConstructor;
import org.axonframework.queryhandling.QueryHandler;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
@RequiredArgsConstructor
public class OrderQueryHandler {

    private final OrderService orderService;

    @QueryHandler
    public Optional<OrderDTO> findOrder(GetOrderQuery query){
        Optional<OrderDTO> orderDTO = orderService.fetchOrder(query.getOrderId());
        return orderDTO;
    }


}
