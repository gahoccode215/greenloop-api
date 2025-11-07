package com.greenloop.product.dto.request;

import com.greenloop.product.enums.ConditionGrade;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class DonationItemCreateRequest {

    @NotBlank(message = "Name is required")
    @Size(max = 100, message = "Name must not exceed 100 characters")
    private String name;

    private String description;

    @NotNull(message = "Condition grade is required")
    private ConditionGrade conditionGrade;

    @NotNull(message = "Eco point value is required")
    @Min(value = 0, message = "Eco point value must be non-negative")
    private Integer ecoPointValue;

    @NotNull(message = "Category ID is required")
    private Long categoryId;
}