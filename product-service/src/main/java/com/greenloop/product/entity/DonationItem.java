package com.greenloop.product.entity;

import com.greenloop.product.enums.ConditionGrade;
import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;

@Entity
@Table(name = "donation_items")
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class DonationItem extends BaseEntity implements Serializable {

    @Column(name = "name", nullable = false)
    private String name;
    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @Column(name = "condition_grade", length = 20)
    @Enumerated(EnumType.STRING)
    private ConditionGrade conditionGrade;

    @Column(name = "eco_point_value")
    private Integer ecoPointValue;

    @Column(name = "convert_product_id")
    private Long convertProductId;

    @Column(name = "media_key")
    private String mediaKey;

    @Column(name = "image_url")
    private String imageUrl;

    @ManyToOne(fetch = FetchType.LAZY)
    private Donation donation;

    @ManyToOne(fetch = FetchType.LAZY)
    private Category category;

    public void updateImage(String imageUrl, String mediaKey) {
        if (imageUrl != null) this.imageUrl = imageUrl;
        if (mediaKey != null) this.mediaKey = mediaKey;
    }

}
