package com.greenloop.reward.dto.request;

import com.greenloop.reward.enums.EcoActionType;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EcoPointRuleRequest {

  @NotBlank(message = "Mã rule không được để trống")
  @Size(max = 20, message = "Mã rule tối đa 20 ký tự")
  private String code;

  @NotBlank(message = "Tên rule không được để trống")
  @Size(max = 100, message = "Tên rule tối đa 100 ký tự")
  private String name;

  @Size(max = 1000, message = "Mô tả tối đa 1000 ký tự")
  private String description;

  @NotNull(message = "Loại hành động không được để trống")
  private EcoActionType actionType;

  @NotNull(message = "Giá trị minPoints không được để trống")
  @Min(value = 0, message = "minPoints phải >= 0")
  private Integer minPoints;

  @NotNull(message = "Giá trị maxPoints không được để trống")
  @Min(value = 1, message = "maxPoints phải >= 1")
  private Integer maxPoints;

  private Long categoryId;
}
