package com.greenloop.order.ghn.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;

import java.util.List;

@Data
@Builder
public class CreateShippingOrderRequest {

    // ========== THÔNG TIN NGƯỜI GỬI (BẮT BUỘC) ==========
    @JsonProperty("from_name")
    private String fromName;  // Tên shop/người gửi

    @JsonProperty("from_phone")
    private String fromPhone;  // SĐT shop

    @JsonProperty("from_address")
    private String fromAddress;  // Địa chỉ kho/shop

    @JsonProperty("from_ward_name")
    private String fromWardName;  // Phường của shop

    @JsonProperty("from_district_name")
    private String fromDistrictName;  // Quận của shop

    @JsonProperty("from_province_name")
    private String fromProvinceName;  // Tỉnh của shop (VD: "HCM", "Hà Nội")

    // ========== THÔNG TIN NGƯỜI NHẬN ==========
    @JsonProperty("to_name")
    private String toName;

    @JsonProperty("to_phone")
    private String toPhone;

    @JsonProperty("to_address")
    private String toAddress;

    @JsonProperty("to_ward_code")
    private String toWardCode;

    @JsonProperty("to_district_id")
    private Integer toDistrictId;

    // ========== THÔNG TIN ĐƠN HÀNG ==========
    @JsonProperty("cod_amount")
    private Integer codAmount;  // Tiền thu hộ

    @JsonProperty("content")
    private String content;

    @JsonProperty("weight")
    private Integer weight;  // Cân nặng (gram)

    @JsonProperty("length")
    private Integer length;  // Chiều dài (cm)

    @JsonProperty("width")
    private Integer width;

    @JsonProperty("height")
    private Integer height;

    // ========== CÁC FIELD BẮT BUỘC KHÁC ==========
    @JsonProperty("service_type_id")
    private Integer serviceTypeId;  // 2 = E-commerce

    @JsonProperty("payment_type_id")
    private Integer paymentTypeId;  // 1 = Shop trả, 2 = Khách trả

    @JsonProperty("required_note")
    private String requiredNote;  // CHOTHUHANG, CHOXEMHANGKHONGTHU, KHONGCHOXEMHANG

    // ========== OPTIONAL ==========
    @JsonProperty("note")
    private String note;  // Ghi chú cho shipper

    @JsonProperty("client_order_code")
    private String clientOrderCode;  // Mã đơn hàng của bạn

    @JsonProperty("insurance_value")
    private Integer insuranceValue;  // Giá trị bảo hiểm

    @JsonProperty("items")
    private List<ItemDetail> items;

    @Data
    @Builder
    public static class ItemDetail {
        private String name;
        private String code;
        private Integer quantity;
        private Integer price;
        private Integer weight;
        private Integer length;
        private Integer width;
        private Integer height;
    }
}
