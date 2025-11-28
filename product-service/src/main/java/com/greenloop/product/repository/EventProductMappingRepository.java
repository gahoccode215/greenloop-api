package com.greenloop.product.repository;

import com.greenloop.product.entity.EventProductMapping;
import com.greenloop.product.enums.EventMappingStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

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

    Optional<EventProductMapping> findByEventIdAndProductId(Long eventId, Long productId);

    boolean existsByEventIdAndProductId(Long eventId, Long productId);

    Long countByStatus(EventMappingStatus status);

    @Query("SELECT m.eventId, COUNT(m) " +
            "FROM EventProductMapping m GROUP BY m.eventId")
    List<Object[]> countProductsByEvent();

}
