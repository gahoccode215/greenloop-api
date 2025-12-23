package com.greenloop.order.entity;

import com.greenloop.order.dto.BankInfoDTO;
import com.greenloop.order.enums.ReturnReason;
import com.greenloop.order.enums.ReturnRequestStatus;
import com.greenloop.order.enums.ReturnType;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "return_requests",
        indexes = {
                @Index(name = "idx_return_order", columnList = "order_id"),
                @Index(name = "idx_return_customer", columnList = "customer_id"),
                @Index(name = "idx_return_status", columnList = "status"),
                @Index(name = "idx_return_requested_at", columnList = "requested_at")
        })
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ReturnRequest {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "return_request_id")
    private Long returnRequestId;

    @Column(name = "order_id", nullable = false, length = 36)
    private String orderId;

    @Column(name = "customer_id", nullable = false)
    private Long customerId;

    @OneToMany(mappedBy = "returnRequest", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<ReturnItem> returnItems = new ArrayList<>();

    @Enumerated(EnumType.STRING)
    @Column(name = "return_reason", nullable = false, length = 50)
    private ReturnReason returnReason;

    @Column(name = "description", columnDefinition = "TEXT", nullable = false)
    private String description;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "images", columnDefinition = "JSON")
    private List<String> images;

    @Enumerated(EnumType.STRING)
    @Column(name = "return_type", nullable = false, length = 20)
    private ReturnType returnType;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "bank_info", columnDefinition = "JSON", nullable = false)
    private BankInfoDTO bankInfo;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 50)
    private ReturnRequestStatus status;

    @Column(name = "return_shipment_id", length = 50)
    private String returnShipmentId;

    @Column(name = "return_tracking_url", length = 255)
    private String returnTrackingUrl;

    @Column(name = "return_carrier", length = 50)
    private String returnCarrier;

    @Column(name = "return_shipping_status")
    private Integer returnShippingStatus;

    @Column(name = "estimated_return_shipping_fee", precision = 10, scale = 2)
    private BigDecimal estimatedReturnShippingFee;

    @Column(name = "actual_return_shipping_fee", precision = 10, scale = 2)
    private BigDecimal actualReturnShippingFee;

    @Column(name = "original_amount", precision = 10, scale = 2)
    private BigDecimal originalAmount;

    @Column(name = "refund_amount", precision = 10, scale = 2)
    private BigDecimal refundAmount;

    @Column(name = "approved_by")
    private Long approvedBy;

    @Column(name = "approved_at")
    private LocalDateTime approvedAt;

    @Column(name = "rejected_by")
    private Long rejectedBy;

    @Column(name = "rejected_at")
    private LocalDateTime rejectedAt;

    @Column(name = "rejected_reason", columnDefinition = "TEXT")
    private String rejectedReason;

    @Column(name = "inspected_by")
    private Long inspectedBy;

    @Column(name = "inspected_at")
    private LocalDateTime inspectedAt;

    @Column(name = "inspection_note", columnDefinition = "TEXT")
    private String inspectionNote;

    @Column(name = "refund_proof_image")
    private String refundProofImage; // URL ảnh bill chuyển khoản


    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "inspection_images", columnDefinition = "JSON")
    private List<String> inspectionImages;

    @Column(name = "requested_at", nullable = false)
    private LocalDateTime requestedAt;

    @Column(name = "returned_at")
    private LocalDateTime returnedAt;

    @Column(name = "completed_at")
    private LocalDateTime completedAt;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = createdAt;
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    public void addReturnItem(ReturnItem item) {
        returnItems.add(item);
        item.setReturnRequest(this);
    }
}
