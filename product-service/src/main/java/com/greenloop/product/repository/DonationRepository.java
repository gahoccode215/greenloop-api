package com.greenloop.product.repository;

import com.greenloop.product.entity.Donation;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DonationRepository extends JpaRepository<Donation, Long>, Specification<Donation> {
    List<Donation> findByEventId(Long eventId);

    List<Donation> findByUserId(Long userId);
}
