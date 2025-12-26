package com.greenloop.order.repository.specification;

import com.greenloop.order.dto.request.TransactionFilterRequest;
import com.greenloop.order.entity.Transaction;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

public class TransactionSpecification {

    public static Specification<Transaction> filterTransactions(
            LocalDateTime from, LocalDateTime to, TransactionFilterRequest filter) {

        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            // Date range
            if (from != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("transactionDate"), from));
            }
            if (to != null) {
                predicates.add(cb.lessThanOrEqualTo(root.get("transactionDate"), to));
            }

            // Transaction type
            if (filter != null && filter.getTransactionType() != null) {
                predicates.add(cb.equal(root.get("transactionType"), filter.getTransactionType()));
            }

            // Order type
            if (filter != null && filter.getOrderType() != null) {
                predicates.add(cb.equal(root.get("orderType"), filter.getOrderType()));
            }

            // Payment method
            if (filter != null && filter.getPaymentMethod() != null) {
                predicates.add(cb.equal(root.get("paymentMethod"), filter.getPaymentMethod()));
            }

            // Status
            if (filter != null && filter.getStatus() != null) {
                predicates.add(cb.equal(root.get("status"), filter.getStatus()));
            }

            // Event ID
            if (filter != null && filter.getEventId() != null) {
                predicates.add(cb.equal(root.get("eventId"), filter.getEventId()));
            }

            // Customer ID
            if (filter != null && filter.getCustomerId() != null) {
                predicates.add(cb.equal(root.get("customerId"), filter.getCustomerId()));
            }

            // Guest purchase
            if (filter != null && filter.getIsGuestPurchase() != null) {
                predicates.add(cb.equal(root.get("isGuestPurchase"), filter.getIsGuestPurchase()));
            }

            // Search keyword
            if (filter != null && filter.getSearchKeyword() != null && !filter.getSearchKeyword().isBlank()) {
                String keyword = "%" + filter.getSearchKeyword().toLowerCase() + "%";
                Predicate searchPredicate = cb.or(
                        cb.like(cb.lower(root.get("orderCode")), keyword),
                        cb.like(cb.lower(root.get("transactionCode")), keyword),
                        cb.like(cb.lower(root.get("guestName")), keyword)
                );
                predicates.add(searchPredicate);
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }
}
