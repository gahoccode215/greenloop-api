package com.greenloop.order.entity;

import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.PaymentMethod;
import com.greenloop.order.enums.PaymentStatus;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

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
@EntityListeners(AuditingEntityListener.class)
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

    @Column(name = "payment_status")
    @Enumerated(EnumType.STRING)
    private PaymentStatus paymentStatus;

    @Column(name = "payment_transaction_id")
    private String paymentTransactionId;

    @Column(name = "payment_order_code")
    private Long paymentOrderCode;

    @Column(name = "payment_method")
    @Enumerated(EnumType.STRING)
    private PaymentMethod paymentMethod;

    @Column(name = "goship_shipment_id", length = 50)
    private String goshipShipmentId;

    @Column(name = "goship_tracking_code", length = 50)
    private String goshipTrackingCode;

    @Column(name = "carrier", length = 20)
    private String carrier;

    @Column(name = "shipping_fee")
    private BigDecimal shippingFee;

    @Column(name = "expected_delivery_time")
    private LocalDateTime expectedDeliveryTime;

    @Column(name = "shipping_status", length = 50)
    private String shippingStatus;

    @Column(name = "selected_rate_id")
    private String selectedRateId;

    @Column(name = "parcel_weight")
    private String parcelWeight;  // gram

    @Column(name = "parcel_width")
    private String parcelWidth;   // cm

    @Column(name = "parcel_height")
    private String parcelHeight;  // cm

    @Column(name = "parcel_length")
    private String parcelLength;  // cm

    @OneToMany(mappedBy = "order", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<OrderItem> orderItems = new ArrayList<>();

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
}
