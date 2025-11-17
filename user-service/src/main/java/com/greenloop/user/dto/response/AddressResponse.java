package com.greenloop.user.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AddressResponse {

  private Long id;
  private String recipientName;
  private String recipientPhone;
  private String addressLine;

  private String ward; // "Phường Bến Nghé"
  private Long wardCode;

  private Long district; // 700100
  private String districtName; // "Quận 1"

  private Long city; // 700000
  private String cityName; // "Hồ Chí Minh"

  private Boolean isDefault;
  private String deliveryNote;
}
