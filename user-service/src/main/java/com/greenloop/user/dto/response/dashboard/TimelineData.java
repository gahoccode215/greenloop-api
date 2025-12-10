package com.greenloop.user.dto.response.dashboard;

import lombok.*;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TimelineData {
    private String date;  // Format: yyyy-MM-dd
    private Long count;
}