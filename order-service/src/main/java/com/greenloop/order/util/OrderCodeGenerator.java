package com.greenloop.order.util;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

public class OrderCodeGenerator {

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyMMdd");

    public static String generateOrderCode() {
        String datePart = LocalDateTime.now().format(DATE_FORMATTER);
        String uniquePart = UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        return String.format("ORD-%s-%s", datePart, uniquePart);
    }
}
