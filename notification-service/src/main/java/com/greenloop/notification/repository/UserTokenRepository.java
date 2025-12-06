package com.greenloop.notification.repository;

import com.greenloop.notification.entity.UserToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserTokenRepository extends JpaRepository<UserToken, Long> {
    List<UserToken> findByUserId(Long userId);
    Optional<UserToken> findByToken(String token);
    void deleteByToken(String token);

}
