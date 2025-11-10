package com.greenloop.order.entity;

import com.greenloop.order.enums.OrderStatus;
import jakarta.persistence.*;
import lombok.*;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
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

    @Embedded
    private ShippingAddress shippingAddress;

    // Thông tin GHN
    @Column(name = "ghn_order_code", length = 50)
    private String ghnOrderCode;

    @Column(name = "shipping_fee")
    private BigDecimal shippingFee;

    @Column(name = "expected_delivery_time")
    private LocalDateTime expectedDeliveryTime;

    @Column(name = "shipping_status", length = 50)
    private String shippingStatus;

    @OneToMany(mappedBy = "order", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<OrderItem> orderItems = new ArrayList<>();
}
