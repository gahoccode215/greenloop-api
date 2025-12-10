package com.greenloop.user.dto.response.dashboard;

import lombok.*;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NewUsersByPeriod {
    private Long today;
    private Long thisWeek;
    private Long thisMonth;
    private Long lastMonth;
}
