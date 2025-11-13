package com.greenloop.reward.repository;

import com.greenloop.reward.entity.EcoPointUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface EcoPointUserRepository extends JpaRepository<EcoPointUser, Long> {
    Optional<EcoPointUser> findByUserId(Long userId);
}
