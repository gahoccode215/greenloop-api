package com.greenloop.reward.repository;

import com.greenloop.reward.entity.VoucherUser;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface VoucherUserRepository extends JpaRepository<VoucherUser, Long> {
  Optional<VoucherUser> findByVoucherIdAndUserId(Long voucherId, Long userId);

  List<VoucherUser> findAllByUserId(Long userId);
}
