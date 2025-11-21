package com.greenloop.product.entity;

import com.greenloop.product.enums.EventMappingStatus;
import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.time.LocalDateTime;

@Entity
@Table(name = "event_product_mappings")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class EventProductMapping extends BaseEntity implements Serializable {

    @Column(name = "event_id", nullable = false)
    private Long eventId;

    @ManyToOne
    @JoinColumn(name = "product_id", nullable = false)
    private Product productId;

    @Column(name = "display_from")
    private LocalDateTime displayFrom;

    @Column(name = "display_to")
    private LocalDateTime displayTo;

    @Column(name = "status", nullable = false)
    @Enumerated(EnumType.STRING)
    private EventMappingStatus status;
}
