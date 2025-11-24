package com.greenloop.order.entity;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

/**
 * Entity lưu lịch sử thay đổi của đơn hàng
 * Mỗi lần đơn hàng thay đổi trạng thái sẽ tạo 1 record mới
 */
@Entity
@Table(name = "order_history",
        indexes = {
                @Index(name = "idx_order_history_order_id", columnList = "order_id"),
                @Index(name = "idx_order_history_created_at", columnList = "created_at")
        }
)
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EntityListeners(AuditingEntityListener.class)
public class OrderHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "order_id", nullable = false)
    private String orderId;

    @Column(name = "event_type", nullable = false, length = 50)
    private String eventType;

    @Column(name = "description", nullable = false)
    private String description;

    @Column(name = "old_value", length = 100)
    private String oldValue;

    @Column(name = "new_value", length = 100)
    private String newValue;

    @Column(name = "changed_by")
    private Long changedBy;

    @Column(name = "changed_by_role", length = 20)
    private String changedByRole;

    private String reason;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;


}
