package com.greenloop.order.dto.request;

import com.greenloop.order.dto.BankInfoDTO;
import com.greenloop.order.enums.ReturnReason;
import com.greenloop.order.enums.ReturnType;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.*;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CreateReturnRequestRequest {

    @NotNull(message = "Vui lòng chọn sản phẩm muốn trả")
    @Size(min = 1, message = "Phải có ít nhất 1 sản phẩm để trả")
    private List<Long> returnOrderItemIds;

    @NotNull(message = "Lý do trả hàng không được để trống")
    private ReturnReason returnReason;

    @NotBlank(message = "Mô tả chi tiết không được để trống")
    @Size(min = 10, max = 1000, message = "Mô tả phải từ 10-1000 ký tự")
    private String description;

    @NotNull(message = "Loại trả hàng không được để trống")
    private ReturnType returnType;

    @Valid
    @NotNull(message = "Thông tin tài khoản ngân hàng không được để trống")
    private BankInfoDTO bankInfo;
}
