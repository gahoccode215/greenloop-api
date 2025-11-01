package com.greenloop.product.entity;

import com.greenloop.product.enums.ConditionGrade;
import com.greenloop.product.enums.ProductStatus;
import com.greenloop.product.enums.ProductType;
import jakarta.persistence.*;
import java.math.BigDecimal;
import java.util.HashSet;
import java.util.Set;
import lombok.*;
import lombok.experimental.SuperBuilder;

@Entity
@Table(name = "products", indexes = {
        @Index(name = "idx_product_code", columnList = "code"),
        @Index(name = "idx_product_status", columnList = "status"),
        @Index(name = "idx_product_category", columnList = "category_id")
})
@Getter
@Setter
@SuperBuilder
@NoArgsConstructor
@AllArgsConstructor
public class Product extends BaseEntity {

    @Column(name = "code", unique = true, nullable = false, length = 50)
    private String code;

    @Column(name = "name", nullable = false)
    private String name;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "category_id", nullable = false)
    private Category category;

    @Column(name = "donation_item_id")
    private Long donationItemId;

    @Column(name = "price", precision = 10, scale = 2)
    private BigDecimal price;

    @Column(name = "eco_point_value")
    private Integer ecoPointValue;

    @Enumerated(EnumType.STRING)
    @Column(name = "condition_grade", length = 20)
    private ConditionGrade conditionGrade;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", length = 20, nullable = false)
    @Builder.Default
    private ProductStatus status = ProductStatus.PENDING;

    @Enumerated(EnumType.STRING)
    @Column(name = "type", length = 20, nullable = false)
    private ProductType type;

    @OneToMany(mappedBy = "product", fetch = FetchType.LAZY, cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private Set<ProductAsset> assets = new HashSet<>();

    public void addAsset(ProductAsset asset) {
        assets.add(asset);
        asset.setProduct(this);
    }

    public void removeAsset(ProductAsset asset) {
        assets.remove(asset);
        asset.setProduct(null);
    }
}
