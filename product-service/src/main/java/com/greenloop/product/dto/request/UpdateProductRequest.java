package com.greenloop.product.dto.request;

import com.greenloop.product.enums.ConditionGrade;
import com.greenloop.product.enums.ProductStatus;
import com.greenloop.product.enums.ProductType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.math.BigDecimal;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class UpdateProductRequest {
    private Long categoryId;
    private String donationItemCode;
    private String productName;
    private String description;
    private BigDecimal price;
    private Integer ecoPointValue;
    private ConditionGrade conditionGrade;
    private ProductStatus status;
    private ProductType type;
}
