package com.greenloop.order.repository.specification;

import com.greenloop.order.dto.request.ReturnRequestFilterRequest;
import com.greenloop.order.entity.ReturnRequest;
import org.springframework.data.jpa.domain.Specification;

import jakarta.persistence.criteria.Predicate;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class ReturnRequestSpecification {

    public static Specification<ReturnRequest> filterReturnRequests(ReturnRequestFilterRequest filter) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (filter.getStatus() != null) {
                predicates.add(criteriaBuilder.equal(root.get("status"), filter.getStatus()));
            }

            if (filter.getReturnReason() != null) {
                predicates.add(criteriaBuilder.equal(root.get("returnReason"), filter.getReturnReason()));
            }

            if (filter.getReturnType() != null) {
                predicates.add(criteriaBuilder.equal(root.get("returnType"), filter.getReturnType()));
            }

            if (filter.getCustomerId() != null) {
                predicates.add(criteriaBuilder.equal(root.get("customerId"), filter.getCustomerId()));
            }

            if (filter.getOrderId() != null && !filter.getOrderId().trim().isEmpty()) {
                predicates.add(criteriaBuilder.equal(root.get("orderId"), filter.getOrderId()));
            }

            if (filter.getSearchKeyword() != null && !filter.getSearchKeyword().trim().isEmpty()) {
                String keyword = "%" + filter.getSearchKeyword().toLowerCase() + "%";
                Predicate orderIdPredicate = criteriaBuilder.like(
                        criteriaBuilder.lower(root.get("orderId")), keyword);
                Predicate descriptionPredicate = criteriaBuilder.like(
                        criteriaBuilder.lower(root.get("description")), keyword);
                predicates.add(criteriaBuilder.or(orderIdPredicate, descriptionPredicate));
            }

            if (filter.getFromDate() != null && !filter.getFromDate().trim().isEmpty()) {
                try {
                    LocalDateTime fromDateTime = LocalDateTime.parse(
                            filter.getFromDate() + "T00:00:00",
                            DateTimeFormatter.ISO_LOCAL_DATE_TIME
                    );
                    predicates.add(criteriaBuilder.greaterThanOrEqualTo(
                            root.get("createdAt"), fromDateTime));
                } catch (Exception ignored) {
                }
            }

            if (filter.getToDate() != null && !filter.getToDate().trim().isEmpty()) {
                try {
                    LocalDateTime toDateTime = LocalDateTime.parse(
                            filter.getToDate() + "T23:59:59",
                            DateTimeFormatter.ISO_LOCAL_DATE_TIME
                    );
                    predicates.add(criteriaBuilder.lessThanOrEqualTo(
                            root.get("createdAt"), toDateTime));
                } catch (Exception ignored) {
                }
            }

            if (filter.getMinAmount() != null) {
                predicates.add(criteriaBuilder.greaterThanOrEqualTo(
                        root.get("originalAmount"), filter.getMinAmount()));
            }

            if (filter.getMaxAmount() != null) {
                predicates.add(criteriaBuilder.lessThanOrEqualTo(
                        root.get("originalAmount"), filter.getMaxAmount()));
            }

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }
}
