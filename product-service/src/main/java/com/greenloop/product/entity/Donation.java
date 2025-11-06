package com.greenloop.product.entity;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "donations")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Donation extends BaseEntity implements Serializable {

    @Column(name = "code", unique = true, nullable = false, length = 25)
    private String code;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "event_id", nullable = false)
    private Long eventId;

    @Column(name = "total_weight")
    private Float totalWeight;

    @Column(name = "note", columnDefinition = "TEXT")
    private String note;

    @Column(name = "inspected_by", nullable = false)
    private Long inspectedBy;


    @OneToMany(mappedBy = "donation", orphanRemoval = true, cascade = CascadeType.ALL)
    private List<DonationItem> donationItems = new ArrayList<>();


}

