package com.greenloop.reward.repository;

import com.greenloop.reward.entity.EcoPointRule;
import com.greenloop.reward.enums.EcoActionType;
import io.lettuce.core.dynamic.annotation.Param;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface EcoPointRuleRepository extends JpaRepository<EcoPointRule, Long> {
    boolean existsByCode(String code);

    boolean existsByActionTypeAndCategoryId(EcoActionType actionType, Long categoryId);

    @Query(
            "SELECT r FROM EcoPointRule r WHERE "
                    + "(:actionType IS NULL OR r.actionType = :actionType) AND "
                    + "(:code IS NULL OR r.code LIKE %:code%) AND "
                    + "(:name IS NULL OR r.name LIKE %:name%)")
    List<EcoPointRule> findAllByFilter(
            @Param("actionType") EcoActionType actionType,
            @Param("code") String code,
            @Param("name") String name);


    Optional<EcoPointRule> findByActionTypeAndCategoryId(EcoActionType actionType, Long categoryId);
}
