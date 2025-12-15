package com.greenloop.product.service.impl;

import com.greenloop.product.dto.request.CategoryRequest;
import com.greenloop.product.dto.response.CategoryResponse;
import com.greenloop.product.entity.Category;
import com.greenloop.product.enums.ErrorCode;
import com.greenloop.product.exception.BusinessException;
import com.greenloop.product.repository.CategoryRepository;
import com.greenloop.product.service.CategoryService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;

@RequiredArgsConstructor
@Service
@Slf4j
public class CategoryServiceImpl implements CategoryService {
    private final CategoryRepository categoryRepository;

    @Override
    public void createCategory(CategoryRequest categoryRequest) {
        log.info("createCategory");
        Category category = Category.builder()
                .name(categoryRequest.getName())
                .description(categoryRequest.getDescription())
                .build();
        categoryRepository.save(category);
    }

    @Override
    public List<CategoryResponse> getCategories() {
        List<Category> categories = categoryRepository.findAll();
        List<CategoryResponse> categoriesResponse = categories.stream().map(
                category -> CategoryResponse.builder()
                        .id(category.getId())
                        .name(category.getName())
                        .description(category.getDescription())
                        .active(category.getIsActive())
                        .createdAt(category.getCreatedAt())
                        .updatedAt(category.getUpdatedAt())
                        .build()
        ).toList();
        return categoriesResponse;
    }

    @Override
    public void updateActiveStatus(Long categoryId) {
        Long currentUserId = getCurrentUserId();
        Category category = categoryRepository.findById(categoryId).orElseThrow(
                () -> new BusinessException(ErrorCode.CATEGORY_NOT_FOUND)
        );
        category.setIsActive(!category.getIsActive());
        category.setUpdatedBy(currentUserId);
        categoryRepository.save(category);
    }

    private Long getCurrentUserId() {
        return Long.valueOf(
                SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
    }

    @Override
    public void updateCategory(Long categoryId, CategoryRequest categoryRequest) {
        Long currentUserId = getCurrentUserId();
        Category category = categoryRepository.findById(categoryId).orElseThrow(
                () -> new BusinessException(ErrorCode.CATEGORY_NOT_FOUND)
        );
        category.setName(categoryRequest.getName());
        category.setDescription(categoryRequest.getDescription());
        category.setUpdatedBy(currentUserId);
        categoryRepository.save(category);
    }
}
