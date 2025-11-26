package com.greenloop.product.dto.response;

import com.greenloop.product.enums.EventMappingStatus;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;

@Getter
@Setter
@Builder
public class EventProductMappingResponse {
    private Long id;
    private Long eventId;
    private LocalDateTime displayFrom;
    private LocalDateTime displayTo;
    private EventMappingStatus status;
}
