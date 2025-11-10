package com.greenloop.order.entity;

import com.greenloop.order.enums.OrderStatus;
import jakarta.persistence.*;
import lombok.*;

import java.math.BigDecimal;
import java.util.List;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Table(name = "orders")
@Entity
@Builder
public class Order {

    @Id
    private String orderId;

    private String orderCode;

    private Long customerId;

    private BigDecimal totalPrice;

    @Enumerated(EnumType.STRING)
    @Column(name = "order_status", nullable = false, length = 20)
    private OrderStatus orderStatus;

    @OneToMany(mappedBy = "order", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<OrderItem> orderItems;
}
