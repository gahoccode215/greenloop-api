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
    private Long id;
    private String eventType;
    private String description;
    private String oldValue;
    private String newValue;
    private String changedByRole;
    private LocalDateTime createdAt;
}
