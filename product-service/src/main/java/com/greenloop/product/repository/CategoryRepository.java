package com.greenloop.product.repository;

import com.greenloop.product.entity.Category;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface CategoryRepository extends JpaRepository<Category, Long> {
    Optional<Category> findByName(String name);

    boolean existsByName(String name);

    @Query("SELECT c.id, c.name, COUNT(p) " +
            "FROM Category c LEFT JOIN c.products p " +
            "GROUP BY c.id, c.name")
    List<Object[]> countProductsByCategory();
}
