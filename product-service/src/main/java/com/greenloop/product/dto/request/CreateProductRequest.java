package com.greenloop.product.dto.request;

import com.greenloop.product.enums.ConditionGrade;
import com.greenloop.product.enums.ProductStatus;
import com.greenloop.product.enums.ProductType;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.math.BigDecimal;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class CreateProductRequest {

    @NotNull(message = "Category ID is required")
    private Long categoryId;

    @NotBlank(message = "Donation item code is required")
    private String donationItemCode;

    @NotBlank(message = "Product name is required")
    @Size(max = 150, message = "Product name must not exceed 150 characters")
    private String productName;

    @Size(max = 2000, message = "Description must not exceed 2000 characters")
    private String description;

    @NotNull(message = "Price is required")
    @DecimalMin(value = "0.01", message = "Price must be greater than 0")
    private BigDecimal price;

    @NotNull(message = "Eco point value is required")
    @Min(value = 0, message = "Eco point value must be >= 0")
    private Integer ecoPointValue;

    @NotNull(message = "Condition grade is required")
    private ConditionGrade conditionGrade;

    @NotNull(message = "Product status is required")
    private ProductStatus status;

    @NotNull(message = "Product type is required")
    private ProductType type;
}
