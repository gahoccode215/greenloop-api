package com.greenloop.order.util;

import com.greenloop.order.repository.OrderRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Component
@RequiredArgsConstructor
public class OrderCodeGenerator {

    private static final DateTimeFormatter FULL_DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd");

    private final OrderRepository orderRepository;

    /**
     * Generate order code cho đơn hàng ONLINE
     * Format: ONL-YYYYMMDD-XXXXX
     * Example: ONL-20251206-00001
     */
    public String generateOrderOnlineCode() {
        LocalDateTime now = LocalDateTime.now();
        String datePart = now.format(FULL_DATE_FORMATTER);
        String prefix = "ONL-" + datePart;

        long count = orderRepository.countByOrderCodeStartingWith(prefix);
        String sequence = String.format("%05d", count + 1);

        return String.format("ONL-%s-%s", datePart, sequence);
    }

    /**
     * Generate order code cho đơn hàng OFFLINE
     * Format: OFF-YYYYMMDD-XXXXX
     * Example: OFF-20251206-00001
     */
    public String generateOrderOfflineCode() {
        LocalDateTime now = LocalDateTime.now();
        String datePart = now.format(FULL_DATE_FORMATTER);
        String prefix = "OFF-" + datePart;

        long count = orderRepository.countByOrderCodeStartingWith(prefix);
        String sequence = String.format("%05d", count + 1);

        return String.format("OFF-%s-%s", datePart, sequence);
    }
}
