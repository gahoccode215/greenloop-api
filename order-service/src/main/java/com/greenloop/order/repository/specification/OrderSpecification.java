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

            if (requestingUserId != null) {
                predicates.add(criteriaBuilder.equal(root.get("customerId"), requestingUserId));
            }

            if (filter.getCustomerId() != null) {
                predicates.add(criteriaBuilder.equal(root.get("customerId"), filter.getCustomerId()));
            }

            if (filter.getStatus() != null) {
                predicates.add(criteriaBuilder.equal(root.get("orderStatus"), filter.getStatus()));
            }

            if (filter.getPaymentStatus() != null) {
                predicates.add(criteriaBuilder.equal(root.get("paymentStatus"), filter.getPaymentStatus()));
            }

            if (filter.getSearchKeyword() != null && !filter.getSearchKeyword().trim().isEmpty()) {
                String searchPattern = "%" + filter.getSearchKeyword().toLowerCase().trim() + "%";
                predicates.add(
                        criteriaBuilder.or(
                                criteriaBuilder.like(criteriaBuilder.lower(root.get("orderCode")), searchPattern),
                                criteriaBuilder.like(criteriaBuilder.lower(root.get("orderId")), searchPattern)
                        )
                );
            }

            if (filter.getFromDate() != null && !filter.getFromDate().trim().isEmpty()) {
                try {
                    LocalDateTime fromDateTime = LocalDate.parse(filter.getFromDate(),
                            DateTimeFormatter.ISO_DATE).atStartOfDay();
                    predicates.add(criteriaBuilder.greaterThanOrEqualTo(root.get("createdAt"), fromDateTime));
                } catch (Exception e) {
                }
            }

            if (filter.getToDate() != null && !filter.getToDate().trim().isEmpty()) {
                try {
                    LocalDateTime toDateTime = LocalDate.parse(filter.getToDate(),
                            DateTimeFormatter.ISO_DATE).atTime(23, 59, 59);
                    predicates.add(criteriaBuilder.lessThanOrEqualTo(root.get("createdAt"), toDateTime));
                } catch (Exception e) {
                }
            }

            if (predicates.isEmpty()) {
                return criteriaBuilder.conjunction();
            }

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }
}
