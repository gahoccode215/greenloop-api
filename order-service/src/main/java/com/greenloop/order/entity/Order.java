package com.greenloop.order.entity;

import com.greenloop.order.enums.OrderStatus;
import com.greenloop.order.enums.OrderType;
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

    @Column(name = "voucher_user_id")
    private Long voucherUserId;

    @Column(name = "voucher_code")
    private String voucherCode;

    @Column(name = "discount_amount")
    private BigDecimal discountAmount;

    private BigDecimal subTotal;

    private BigDecimal totalPrice;

    @Enumerated(EnumType.STRING)
    @Column(name = "order_status", nullable = false, length = 20)
    private OrderStatus orderStatus;

    @Embedded
    private ShippingAddress shippingAddress;

    @Column(name = "goship_shipment_id", length = 50)
    private String goshipShipmentId;

    @Column(name = "goship_tracking_url")
    private String goshipTrackingUrl;

    @Column(name = "carrier", length = 20)
    private String carrier;

    @Column(name = "shipping_fee")
    private BigDecimal shippingFee;

    @Column(name = "expected_delivery_time")
    private LocalDateTime expectedDeliveryTime;

    @Column(name = "shipping_status")
    private Integer shippingStatus;

    @Column(name = "selected_rate_id", length = 50)
    private String selectedRateId;

    @Column(name = "parcel_weight", length = 20)
    private String parcelWeight;

    @Column(name = "parcel_width", length = 20)
    private String parcelWidth;

    @Column(name = "parcel_height", length = 20)
    private String parcelHeight;

    @Column(name = "parcel_length", length = 20)
    private String parcelLength;

    @Column(name = "payment_status")
    @Enumerated(EnumType.STRING)
    private PaymentStatus paymentStatus;

    @Column(name = "earned_eco_points")
    private Integer earnedEcoPoints;

    @Column(name = "payment_transaction_id")
    private String paymentTransactionId;

    @Column(name = "payment_order_code")
    private Long paymentOrderCode;

    @Column(name = "payment_method")
    @Enumerated(EnumType.STRING)
    private PaymentMethod paymentMethod;

    @Column(name = "event_id")
    private Long eventId;

    @Column(name = "eco_points_earned")
    private Integer ecoPointsEarned;

    @Enumerated(EnumType.STRING)
    @Column(name = "order_type")
    private OrderType orderType = OrderType.ONLINE;

    @Column(name = "is_guest_purchase")
    private Boolean isGuestPurchase = false;

    @Column(name = "guest_name")
    private String guestName;

    @Column(name = "guest_phone")
    private String guestPhone;

    @Column(name = "note")
    private String note;


    @OneToMany(mappedBy = "order", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<OrderItem> orderItems = new ArrayList<>();

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "created_by")
    private String createdBy;

    @LastModifiedDate
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;
}
