package com.greenloop.order.query.handler;

import com.greenloop.order.query.GetOrderQuery;
import com.greenloop.order.service.OrderService;
import lombok.RequiredArgsConstructor;
import org.axonframework.queryhandling.QueryHandler;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class OrderQueryHandler {

    private final OrderService orderService;

    @QueryHandler
    public OrderDTO findOrder(GetOrderQuery query){
        OrderDTO orderDTO = orderService.fetchOrder(query.getOrderId());
        return orderDTO;
    }


}
