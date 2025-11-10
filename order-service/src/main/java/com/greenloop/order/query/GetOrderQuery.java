package com.greenloop.order.query;

import lombok.Value;

@Value
public class GetOrderQuery {
    private final String orderId;
}
