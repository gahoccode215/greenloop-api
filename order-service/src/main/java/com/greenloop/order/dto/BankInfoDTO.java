package com.greenloop.order.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class BankInfoDTO {
    private String bankName;
    private String accountNumber;
    private String accountName;
}
