package com.greenloop.reward.entity;


import com.greenloop.reward.enums.EcoActionType;
import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;

@Entity
@Table(name = "eco_point_rules")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EcoPointRule extends BaseEntity implements Serializable {

    @Column(name = "code", nullable = false, unique = true, length = 20)
    private String code;

    @Column(name = "name", nullable = false, length = 100)
    private String name;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @Column(name = "action_type", nullable = false, length = 50)
    @Enumerated(EnumType.STRING)
    private EcoActionType actionType;

    @Column(name = "min_points", nullable = false)
    private Integer minPoints;

    @Column(name = "max_points", nullable = false)
    private Integer maxPoints;

    @Column(name = "category_id")
    private Long categoryId;
}
