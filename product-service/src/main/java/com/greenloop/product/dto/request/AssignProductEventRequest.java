package com.greenloop.product.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class AssignProductEventRequest {
    private Long eventId;
    private List<Long> productIds;
    private LocalDateTime displayTo;
    private LocalDateTime displayFrom;
}
