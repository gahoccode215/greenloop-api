package com.greenloop.order.util;

import com.greenloop.order.repository.OrderRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OrderCodeGenerator {

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyMMdd");
    private static final DateTimeFormatter FULL_DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd");

    private final OrderRepository orderRepository;

    // Online order
    public static String generateOrderCode() {
        String datePart = LocalDateTime.now().format(DATE_FORMATTER);
        String uniquePart = UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        return String.format("ORD-%s-%s", datePart, uniquePart);
    }

    // Offline order - ALL IN ONE
    public String generateOrderOfflineCode() {
        LocalDateTime now = LocalDateTime.now();
        String datePart = now.format(FULL_DATE_FORMATTER);
        String prefix = "OFF-" + datePart;

        long count = orderRepository.countByOrderCodeStartingWith(prefix);
        String sequence = String.format("%05d", count + 1);

        return String.format("OFF-%s-%s", datePart, sequence);
    }
}
