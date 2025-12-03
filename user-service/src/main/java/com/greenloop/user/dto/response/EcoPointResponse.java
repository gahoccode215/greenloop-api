package com.greenloop.user.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EcoPointResponse {
    private Long id;
    private Long userId;
    private Integer totalPoints;
    private Integer lifetimePoints;
    private String status;
    private List<Object> transactions;
}
