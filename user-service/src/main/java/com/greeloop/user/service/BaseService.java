package com.greeloop.user.service;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public abstract class BaseService<T, ID> {

    protected abstract JpaRepository<T, ID> getRepository();

    protected Pageable createPageable(int page, int size, String sortBy, String sortDir) {
        Sort sort = sortDir.equalsIgnoreCase("ASC")
                ? Sort.by(sortBy).ascending()
                : Sort.by(sortBy).descending();
        return PageRequest.of(page, size, sort);
    }

    protected Page<T> findAll(Specification<T> spec, Pageable pageable) {
        if (getRepository() instanceof JpaSpecificationExecutor) {
            return ((JpaSpecificationExecutor<T>) getRepository()).findAll(spec, pageable);
        }
        throw new UnsupportedOperationException("Repository unsupported specification");
    }
}
