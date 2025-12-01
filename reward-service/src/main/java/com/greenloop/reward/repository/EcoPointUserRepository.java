package com.greenloop.reward.repository;

import com.greenloop.reward.entity.EcoPointUser;
import com.greenloop.reward.enums.EcoPointStatus;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface EcoPointUserRepository extends JpaRepository<EcoPointUser, Long> {
  Optional<EcoPointUser> findByUserId(Long userId);

  Long countByStatus(EcoPointStatus status);

  @Query(
      "SELECT u.userId, u.totalPoints, u.lifetimePoints "
          + "FROM EcoPointUser u ORDER BY u.totalPoints DESC")
  List<Object[]> findTopUsers();
}
