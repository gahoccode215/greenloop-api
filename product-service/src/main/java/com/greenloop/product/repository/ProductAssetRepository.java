package com.greenloop.product.repository;

import com.greenloop.product.entity.ProductAsset;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ProductAssetRepository extends JpaRepository<ProductAsset, Long> {
}
