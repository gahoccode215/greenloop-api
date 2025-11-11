package com.greenloop.order.util;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.atomic.AtomicLong;

public class OrderCodeGenerator {

    private static final AtomicLong counter = new AtomicLong(0);
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyMMdd");

    public static String generateOrderCode() {
        String datePart = LocalDateTime.now().format(DATE_FORMATTER);
        long sequence = counter.incrementAndGet() % 10000;
        return String.format("ORD-%s-%04d", datePart, sequence);
    }
}
