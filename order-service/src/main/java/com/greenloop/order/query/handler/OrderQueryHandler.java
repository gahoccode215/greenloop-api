package com.greenloop.order.query.handler;

import com.greenloop.order.dto.response.OrderResponse;
import com.greenloop.order.dto.response.PageResponseDTO;
import com.greenloop.order.exception.OrderNotFoundException;
import com.greenloop.order.query.GetAllOrdersQuery;
import com.greenloop.order.query.GetOrderQuery;
import com.greenloop.order.service.OrderService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.axonframework.queryhandling.QueryHandler;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class OrderQueryHandler {

    private final OrderService orderService;

    @QueryHandler
    public OrderResponse handle(GetOrderQuery query) {
        log.info("Handling GetOrderQuery for orderId: {}", query.getOrderId());
        OrderResponse response = orderService.getOrderById(query.getOrderId());

        if (response == null) {
            throw new OrderNotFoundException(query.getOrderId());
        }

        return response;
    }

//    @QueryHandler
//    public PageResponseDTO<OrderResponse> handle(GetAllOrdersQuery query) {
//        log.info("Handling GetAllOrdersQuery for user: {}", query.getRequestingUserId());
//        return orderService.getAllOrders(query.getRequestingUserId(), query.getFilter());
//    }
}
