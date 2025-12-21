package com.greenloop.reward.repository;

import com.greenloop.reward.entity.EcoPointUser;
import com.greenloop.reward.enums.EcoPointStatus;
import java.util.List;
import java.util.Optional;

import com.greenloop.reward.enums.SourceType;
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

  @Query(
      "SELECT u.userId, u.totalPoints, u.lifetimePoints "
          + "FROM EcoPointUser u ORDER BY u.lifetimePoints DESC LIMIT 10")
  List<Object[]> findTopLifetimeUsers();

  @Query(
      "SELECT COUNT(u) FROM EcoPointUser u "
          + "WHERE u.lifetimePoints > ("
          + "   SELECT eu.lifetimePoints FROM EcoPointUser eu WHERE eu.userId = :userId"
          + ")")
  Long countUsersWithMoreLifetimePoints(Long userId);

}
