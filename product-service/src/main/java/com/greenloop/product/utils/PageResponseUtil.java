package com.greenloop.product.utils;

import com.greenloop.product.dto.response.PageResponseDTO;
import org.springframework.data.domain.Page;

public class PageResponseUtil {

    public static <T> PageResponseDTO<T> toPageResponse(Page<T> page) {
        return PageResponseDTO.<T>builder()
                .content(page.getContent())
                .pageNumber(page.getNumber())
                .pageSize(page.getSize())
                .totalElements(page.getTotalElements())
                .totalPages(page.getTotalPages())
                .first(page.isFirst())
                .last(page.isLast())
                .empty(page.isEmpty())
                .build();
    }
}
