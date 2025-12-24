package com.greenloop.order.util;

import com.greenloop.order.repository.TransactionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Component
@RequiredArgsConstructor
public class TransactionCodeGenerator {

    private static final DateTimeFormatter FULL_DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd");

    private final TransactionRepository transactionRepository;

    /**
     * Generate transaction code for payment
     * Format: TXN-YYYYMMDD-XXXXX
     * Example: TXN-20251224-00001
     */
    public String generateTransactionCode() {
        LocalDateTime now = LocalDateTime.now();
        String datePart = now.format(FULL_DATE_FORMATTER);
        String prefix = "TXN-" + datePart;

        long count = transactionRepository.countByTransactionCodeStartingWith(prefix);
        String sequence = String.format("%05d", count + 1);

        return String.format("TXN-%s-%s", datePart, sequence);
    }

    /**
     * Generate refund transaction code
     * Format: RFD-YYYYMMDD-XXXXX
     * Example: RFD-20251224-00001
     */
    public String generateRefundCode() {
        LocalDateTime now = LocalDateTime.now();
        String datePart = now.format(FULL_DATE_FORMATTER);
        String prefix = "RFD-" + datePart;

        long count = transactionRepository.countByTransactionCodeStartingWith(prefix);
        String sequence = String.format("%05d", count + 1);

        return String.format("RFD-%s-%s", datePart, sequence);
    }
}
