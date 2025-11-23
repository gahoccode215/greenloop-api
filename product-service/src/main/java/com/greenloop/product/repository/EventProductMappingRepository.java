package com.greenloop.product.repository;

import com.greenloop.product.entity.EventProductMapping;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface EventProductMappingRepository extends JpaRepository<EventProductMapping, Long> {

    @Query("""
                SELECT m FROM EventProductMapping m
                WHERE m.product.id = :productId
                  AND m.eventId <> :eventId
                  AND m.displayFrom <= :displayTo
                  AND m.displayTo >= :displayFrom
            """)
    List<EventProductMapping> findOverlappingAssignments(
            @Param("productId") Long productId,
            @Param("eventId") Long eventId,
            @Param("displayFrom") LocalDateTime displayFrom,
            @Param("displayTo") LocalDateTime displayTo
    );


    List<EventProductMapping> findByEventId(Long eventId);
}
