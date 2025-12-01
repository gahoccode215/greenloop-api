package com.greenloop.reward.worker;

import com.greenloop.reward.entity.Voucher;
import com.greenloop.reward.entity.VoucherUser;
import com.greenloop.reward.enums.VoucherStatus;
import com.greenloop.reward.enums.VoucherUserStatus;
import com.greenloop.reward.repository.VoucherRepository;
import com.greenloop.reward.repository.VoucherUserRepository;
import java.time.LocalDateTime;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
@Slf4j
public class VoucherStatusScheduler {

  private final VoucherRepository voucherRepository;
  private final VoucherUserRepository voucherUserRepository;

  @Scheduled(cron = "0 0 * * * *") // Chạy mỗi giờ vào phút 0
  @Transactional
  public void updateExpiredVouchers() {
    log.info("Starting scheduled voucher expiry update");

    LocalDateTime now = LocalDateTime.now();

    try {
      int expiredVoucherCount = updateExpiredVouchers(now);

      int expiredVoucherUserCount = updateExpiredVoucherUsers();

      log.info(
          "Voucher expiry update completed - Expired Vouchers: {}, Expired VoucherUsers: {}",
          expiredVoucherCount,
          expiredVoucherUserCount);

    } catch (Exception e) {
      log.error("Error updating expired vouchers: {}", e.getMessage(), e);
    }
  }

  private int updateExpiredVouchers(LocalDateTime now) {
    List<Voucher> expiredVouchers =
        voucherRepository.findActiveVouchersBeforeExpiryDate(VoucherStatus.ACTIVE, true, now);

    if (expiredVouchers.isEmpty()) {
      log.debug("No vouchers to expire");
      return 0;
    }

    expiredVouchers.forEach(
        voucher -> {
          voucher.setStatus(VoucherStatus.EXPIRED);
          log.debug(
              "Voucher {} ({}) changed to EXPIRED. Expiry date: {}",
              voucher.getCode(),
              voucher.getName(),
              voucher.getExpiryDate());
        });

    voucherRepository.saveAll(expiredVouchers);
    return expiredVouchers.size();
  }

  private int updateExpiredVoucherUsers() {
    List<VoucherUser> expiredVoucherUsers =
        voucherUserRepository.findAvailableVoucherUsersWithExpiredVouchers(
            VoucherUserStatus.AVAILABLE, VoucherStatus.EXPIRED, true);

    if (expiredVoucherUsers.isEmpty()) {
      log.debug("No voucher users to expire");
      return 0;
    }

    expiredVoucherUsers.forEach(
        voucherUser -> {
          voucherUser.setStatus(VoucherUserStatus.EXPIRED);
          log.debug(
              "VoucherUser ID {} for user {} changed to EXPIRED (Voucher: {})",
              voucherUser.getId(),
              voucherUser.getUserId(),
              voucherUser.getVoucher().getCode());
        });

    voucherUserRepository.saveAll(expiredVoucherUsers);
    return expiredVoucherUsers.size();
  }

  @Scheduled(cron = "0 0 3 * * SUN") // Chủ nhật 3:00 AM
  @Transactional
  public void deactivateOutOfStockVouchers() {
    log.info("Starting scheduled out-of-stock voucher deactivation");

    try {
      List<Voucher> activeVouchers =
          voucherRepository.findByStatusAndIsActive(VoucherStatus.ACTIVE, true);

      int deactivatedCount = 0;
      for (Voucher voucher : activeVouchers) {
        if (voucher.getAvailableQuantity() <= 0) {
          voucher.setActive(false);
          deactivatedCount++;
          log.debug(
              "Voucher {} changed to OUT_OF_STOCK (no quantity available)", voucher.getCode());
        }
      }

      if (deactivatedCount > 0) {
        voucherRepository.saveAll(activeVouchers);
      }

      log.info(
          "Out-of-stock voucher deactivation completed - {} vouchers deactivated",
          deactivatedCount);

    } catch (Exception e) {
      log.error("Error deactivating out-of-stock vouchers: {}", e.getMessage(), e);
    }
  }
}
