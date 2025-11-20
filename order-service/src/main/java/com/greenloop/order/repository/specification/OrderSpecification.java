package com.greenloop.order.repository.specification;

import com.greenloop.order.dto.request.OrderFilterRequest;
import com.greenloop.order.entity.Order;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class OrderSpecification {

    public static Specification<Order> filterOrders(Long requestingUserId, OrderFilterRequest filter) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            // 1. Filter by customerId (if user is customer, not admin)
            if (requestingUserId != null) {
                predicates.add(criteriaBuilder.equal(root.get("customerId"), requestingUserId));
            }

            // 2. Filter by customerId from request (admin can filter by specific customer)
            if (filter.getCustomerId() != null) {
                predicates.add(criteriaBuilder.equal(root.get("customerId"), filter.getCustomerId()));
            }

            // 3. Filter by order status
            if (filter.getStatus() != null) {
                predicates.add(criteriaBuilder.equal(root.get("orderStatus"), filter.getStatus()));
            }

            // 4. Filter by payment status
            if (filter.getPaymentStatus() != null) {
                predicates.add(criteriaBuilder.equal(root.get("paymentStatus"), filter.getPaymentStatus()));
            }

            // 5. Search by keyword (orderCode or orderId)
            if (filter.getSearchKeyword() != null && !filter.getSearchKeyword().trim().isEmpty()) {
                String searchPattern = "%" + filter.getSearchKeyword().toLowerCase().trim() + "%";
                predicates.add(
                        criteriaBuilder.or(
                                criteriaBuilder.like(criteriaBuilder.lower(root.get("orderCode")), searchPattern),
                                criteriaBuilder.like(criteriaBuilder.lower(root.get("orderId")), searchPattern)
                        )
                );
            }

            // 6. Filter by date range
            if (filter.getFromDate() != null && !filter.getFromDate().trim().isEmpty()) {
                try {
                    LocalDateTime fromDateTime = LocalDate.parse(filter.getFromDate(),
                            DateTimeFormatter.ISO_DATE).atStartOfDay();
                    predicates.add(criteriaBuilder.greaterThanOrEqualTo(root.get("createdAt"), fromDateTime));
                } catch (Exception e) {
                    // Invalid date format, skip this filter
                }
            }

            if (filter.getToDate() != null && !filter.getToDate().trim().isEmpty()) {
                try {
                    LocalDateTime toDateTime = LocalDate.parse(filter.getToDate(),
                            DateTimeFormatter.ISO_DATE).atTime(23, 59, 59);
                    predicates.add(criteriaBuilder.lessThanOrEqualTo(root.get("createdAt"), toDateTime));
                } catch (Exception e) {
                    // Invalid date format, skip this filter
                }
            }

            if (predicates.isEmpty()) {
                return criteriaBuilder.conjunction();
            }

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }
}
