package com.greenloop.order.command.event;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;

@Data
public class OrderCreatedEvent {
    private  String orderId;
    private  String orderCode;
    private  Long customerId;
    private  String orderStatus;
    private  BigDecimal totalPrice;

}
