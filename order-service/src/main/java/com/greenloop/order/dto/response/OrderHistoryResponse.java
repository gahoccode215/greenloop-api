package com.greenloop.order.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OrderHistoryResponse {

    // ID của history record
    private Long id;

    // Loại sự kiện (ORDER_CREATED, SHIPPING_STATUS_CHANGED, etc.)
    private String eventType;

    // Mô tả chi tiết (hiển thị cho user)
    private String description;

    // Giá trị cũ (nếu có)
    private String oldValue;

    // Giá trị mới
    private String newValue;

    // Vai trò người thực hiện (CUSTOMER, STAFF, SYSTEM)
    private String changedByRole;

    // Thời gian xảy ra sự kiện
    private LocalDateTime createdAt;
}
