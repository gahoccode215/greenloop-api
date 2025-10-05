package com.greeloop.user.specification;

import org.springframework.data.jpa.domain.Specification;

import java.util.List;

public class GenericSpecifications {

    public static <T> Specification<T> fieldEquals(String fieldName, Object value) {
        return (root, query, cb) ->
                value == null ? null : cb.equal(root.get(fieldName), value);
    }

    public static <T> Specification<T> fieldContains(String fieldName, String value) {
        return (root, query, cb) ->
                value == null ? null : cb.like(cb.lower(root.get(fieldName)), "%" + value.toLowerCase() + "%");
    }

    public static <T> Specification<T> fieldIn(String fieldName, List<?> values) {
        return (root, query, cb) ->
                values == null || values.isEmpty() ? null : root.get(fieldName).in(values);
    }
}
