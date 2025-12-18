package com.greenloop.product.repository;

import com.greenloop.product.entity.DonationItem;
import com.greenloop.product.entity.Product;
import com.greenloop.product.enums.ConditionGrade;
import com.greenloop.product.enums.DonationItemStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface DonationItemRepository extends JpaRepository<DonationItem, Long>, JpaSpecificationExecutor<DonationItem> {
    List<DonationItem> findAllByCodeIn(List<String> codes);

    Optional<DonationItem> findByCode(String code);

    Long countByStatus(DonationItemStatus status);

    Long countByConditionGrade(ConditionGrade grade);

}
