package com.greenloop.order.dto.request.order.offline;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@NoArgsConstructor
@AllArgsConstructor
public class POSCustomer {


    @NotBlank(message = "Customer type không được để trống")
    @Pattern(regexp = "GUEST|MEMBER", message = "Customer type phải là GUEST hoặc MEMBER")
    private String type;

    private Long customerId;

    private String phoneNumber;


    private String name;
}
