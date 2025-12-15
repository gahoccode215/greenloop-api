package com.greenloop.product.repository;

import com.greenloop.product.entity.Product;
import com.greenloop.product.enums.ConditionGrade;
import com.greenloop.product.enums.ProductStatus;
import com.greenloop.product.enums.ProductType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface ProductRepository extends JpaRepository<Product, Long>,
        JpaSpecificationExecutor<Product> {

    Long countByStatus(ProductStatus status);

    Long countByType(ProductType type);

    Long countByConditionGrade(ConditionGrade grade);

    @Query("SELECT p.id, p.name, COUNT(m) " +
            "FROM Product p JOIN p.eventMappings m " +
            "WHERE m.status = 'SOLD_OUT' " +
            "GROUP BY p.id, p.name ORDER BY COUNT(m) DESC")
    List<Object[]> findTopSoldProducts();

    Optional<Product> findByCode(String code);

}
