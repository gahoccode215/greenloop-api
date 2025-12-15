package com.greenloop.product.service;

import com.greenloop.product.dto.request.CategoryRequest;
import com.greenloop.product.dto.response.CategoryResponse;

import java.util.List;

public interface CategoryService {
    void createCategory(CategoryRequest categoryRequest);

    List<CategoryResponse> getCategories();

    void updateActiveStatus(Long categoryId);

    void updateCategory(Long categoryId, CategoryRequest categoryRequest);

}
