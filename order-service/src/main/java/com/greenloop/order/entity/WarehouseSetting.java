package com.greenloop.order.entity;

import lombok.*;
import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "warehouse_setting")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class WarehouseSetting {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String phone;

    @Column(nullable = false)
    private String address;

    @Column(nullable = false)
    private Long wardCode;

    @Column(nullable = false)
    private String wardName;

    @Column(nullable = false)
    private Integer districtId;

    @Column(nullable = false)
    private String districtName;

    @Column(nullable = false)
    private Integer cityId;

    @Column(nullable = false)
    private String cityName;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
