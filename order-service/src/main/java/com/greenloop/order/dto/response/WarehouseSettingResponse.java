package com.greenloop.order.dto.response;

import lombok.*;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class WarehouseSettingResponse {

    private Long id;
    private String name;
    private String phone;
    private String address;
    private Long wardCode;
    private String wardName;
    private Integer districtId;
    private String districtName;
    private Integer cityId;
    private String cityName;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
}
