package com.greenloop.reward.repository;

import com.greenloop.reward.entity.EcoPointUser;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface EcoPointUserRepository extends JpaRepository<EcoPointUser, Long> {
  Optional<EcoPointUser> findByUserId(Long userId);
}
