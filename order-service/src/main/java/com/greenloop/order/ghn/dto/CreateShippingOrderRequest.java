package com.greenloop.order.ghn.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class CreateShippingOrderRequest {

    @JsonProperty("to_name")
    private String toName;  // Tên người nhận

    @JsonProperty("to_phone")
    private String toPhone;  // SĐT người nhận

    @JsonProperty("to_address")
    private String toAddress;  // Địa chỉ người nhận

    @JsonProperty("to_ward_code")
    private String toWardCode;  // Mã phường/xã

    @JsonProperty("to_district_id")
    private Integer toDistrictId;  // Mã quận/huyện

    @JsonProperty("cod_amount")
    private Integer codAmount;  // Tiền thu hộ (COD)

    @JsonProperty("content")
    private String content;  // Nội dung đơn hàng

    @JsonProperty("weight")
    private Integer weight;  // Cân nặng (gram)

    @JsonProperty("length")
    private Integer length;  // Chiều dài (cm)

    @JsonProperty("width")
    private Integer width;  // Chiều rộng (cm)

    @JsonProperty("height")
    private Integer height;  // Chiều cao (cm)

    @JsonProperty("service_type_id")
    private Integer serviceTypeId;  // Loại dịch vụ (1: Nhanh, 2: Chuẩn)

    @JsonProperty("payment_type_id")
    private Integer paymentTypeId;  // 1: Shop trả phí, 2: Người nhận trả

    @JsonProperty("required_note")
    private String requiredNote;  // CHOTHUHANG, CHOXEMHANGKHONGTHU, KHONGCHOXEMHANG

    @JsonProperty("items")
    private List<ItemDetail> items;  // Danh sách sản phẩm

    @Data
    @Builder
    public static class ItemDetail {
        private String name;
        private Integer quantity;
        private Integer price;
    }
}
