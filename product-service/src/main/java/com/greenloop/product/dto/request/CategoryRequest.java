package com.greenloop.product.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class CategoryRequest {
    @NotBlank(message = "Category name must not be blank")
    @NotEmpty(message = "Category name must not be empty")
    private String name;

    @NotBlank(message = "Category description must not be blank")
    @NotEmpty(message = "Category description must not be empty")
    private String description;

}
