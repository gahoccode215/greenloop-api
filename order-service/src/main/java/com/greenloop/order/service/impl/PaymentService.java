package com.greenloop.order.service.impl;

import org.springframework.stereotype.Service;
import lombok.extern.slf4j.Slf4j;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigDecimal;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;

@Service
@Slf4j
public class PaymentService {

    private final String vnp_TmnCode = "M0R9Z6E1";
    private final String vnp_HashSecret = "6Z3AGDLVVDYXEAE3JKBNI6LN2ARZXXST";
    private final String vnp_Url = "https://sandbox.vnpayment.vn/paymentv2/vpcpay.html";
    private final String vnp_ReturnUrl = "http://localhost:5173/payment-success";

    public String createPaymentUrl(String orderId, BigDecimal amount, String ipAddress) {
        try {
            log.info("=== BẮT ĐẦU TẠO PAYMENT URL ===");
            log.info("Order ID: {}", orderId);
            log.info("Amount: {} VND", amount);
            log.info("IP Address: {}", ipAddress);

            Map<String, String> params = new TreeMap<>();

            params.put("vnp_Version", "2.1.0");
            params.put("vnp_Command", "pay");
            params.put("vnp_TmnCode", vnp_TmnCode);

            long amountInCents = amount.longValue() * 100;
            params.put("vnp_Amount", String.valueOf(amountInCents));
            log.info("Amount sau khi x100: {}", amountInCents);

            params.put("vnp_CurrCode", "VND");
            params.put("vnp_TxnRef", orderId);

            String orderInfo = "Thanh toan don hang " + orderId.replace("-", "");
            params.put("vnp_OrderInfo", orderInfo);

            params.put("vnp_OrderType", "other");
            params.put("vnp_Locale", "vn");
            params.put("vnp_ReturnUrl", vnp_ReturnUrl);
            params.put("vnp_IpAddr", (ipAddress != null && !ipAddress.isEmpty()) ? ipAddress : "127.0.0.1");

            SimpleDateFormat sdf = new SimpleDateFormat("yyyyMMddHHmmss");
            sdf.setTimeZone(TimeZone.getTimeZone("Asia/Ho_Chi_Minh"));

            String createDate = sdf.format(new Date());
            params.put("vnp_CreateDate", createDate);
            log.info("CreateDate: {}", createDate);

            Calendar expireCalendar = Calendar.getInstance(TimeZone.getTimeZone("Asia/Ho_Chi_Minh"));
            expireCalendar.add(Calendar.MINUTE, 15);
            String expireDate = sdf.format(expireCalendar.getTime());
            params.put("vnp_ExpireDate", expireDate);
            log.info("ExpireDate: {}", expireDate);

            params.forEach((key, value) -> log.info("  {} = {}", key, value));

            StringBuilder hashData = new StringBuilder();
            StringBuilder query = new StringBuilder();

            Iterator<Map.Entry<String, String>> itr = params.entrySet().iterator();
            while (itr.hasNext()) {
                Map.Entry<String, String> entry = itr.next();
                String fieldName = entry.getKey();
                String fieldValue = entry.getValue();

                if (fieldValue != null && !fieldValue.isEmpty()) {
                    hashData.append(fieldName);
                    hashData.append('=');
                    hashData.append(fieldValue);

                    query.append(URLEncoder.encode(fieldName, StandardCharsets.US_ASCII.toString()));
                    query.append('=');
                    query.append(URLEncoder.encode(fieldValue, StandardCharsets.US_ASCII.toString()));

                    if (itr.hasNext()) {
                        query.append('&');
                        hashData.append('&');
                    }
                }
            }

            String hashDataStr = hashData.toString();
            log.info("=== HASH DATA (dùng để tạo chữ ký) ===");
            log.info("{}", hashDataStr);

            String secureHash = hmacSHA512(vnp_HashSecret, hashDataStr);
            log.info("=== SECURE HASH ===");
            log.info("{}", secureHash);

            String queryUrl = query.toString();
            // V2.1.0 có thể không cần gửi vnp_SecureHashType, nhưng thêm cũng không sao nếu config phù hợp
            // queryUrl += "&vnp_SecureHashType=HmacSHA512";
            queryUrl += "&vnp_SecureHash=" + secureHash;

            String fullUrl = vnp_Url + "?" + queryUrl;
            log.info("=== PAYMENT URL ===");
            log.info("{}", fullUrl);
            log.info("=== KẾT THÚC ===");
            return fullUrl;

        } catch (Exception e) {
            log.error("=== LỖI TẠO PAYMENT URL ===");
            log.error("Order: {}", orderId, e);
            throw new RuntimeException("Failed to create payment URL", e);
        }
    }


    private String hmacSHA512(String key, String data) throws Exception {
        Mac hmac512 = Mac.getInstance("HmacSHA512");
        SecretKeySpec secretKeySpec = new SecretKeySpec(
                key.getBytes(StandardCharsets.UTF_8),
                "HmacSHA512"
        );
        hmac512.init(secretKeySpec);
        byte[] hash = hmac512.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash);
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}