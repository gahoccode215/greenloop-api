package com.greenloop.reward.worker;

import com.greenloop.reward.dto.event.NotificationEvent;
import com.greenloop.reward.entity.Voucher;
import com.greenloop.reward.entity.VoucherUser;
import com.greenloop.reward.enums.VoucherStatus;
import com.greenloop.reward.enums.VoucherUserStatus;
import com.greenloop.reward.repository.VoucherRepository;
import com.greenloop.reward.repository.VoucherUserRepository;
import java.time.LocalDateTime;
import java.util.List;

import com.greenloop.reward.service.NotificationProducer;
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
  private final NotificationProducer notificationProducer;


    @Scheduled(cron = "0 0 * * * *") // chạy mỗi giờ
    @Transactional
    public void updateExpiredVouchers() {
        log.info("Starting scheduled voucher expiry update");

        LocalDateTime now = LocalDateTime.now();

        try {
            try {
                int nearExpiryCount = notifyVoucherExpiringSoon(now);
            } catch (Exception e) {
                log.info("Exception in updateExpiredVouchers", e);
            }

            int expiredVoucherCount = updateExpiredVouchers(now);

            int expiredVoucherUserCount = updateExpiredVoucherUsers();

           log.info("Voucher expiry update completed - {} vouchers expired, {} voucher users expired",
                    expiredVoucherCount, expiredVoucherUserCount);

        } catch (Exception e) {
            log.error("Error updating vouchers: {}", e.getMessage(), e);
        }
    }

    private int notifyVoucherExpiringSoon(LocalDateTime now) {

        LocalDateTime tomorrow = now.plusDays(1);

        List<VoucherUser> voucherUsers =
                voucherUserRepository.findVoucherUsersExpiringInOneDay(
                        VoucherUserStatus.AVAILABLE,
                        now,
                        tomorrow);

        if (voucherUsers.isEmpty()) {
            return 0;
        }

        voucherUsers.forEach(vu -> {
            notificationProducer.sendNotificationMessage(
                    NotificationEvent.builder()
                            .userId(vu.getUserId())
                            .title("Voucher sắp hết hạn")
                            .message("Voucher " + vu.getVoucher().getName()
                                    + " sẽ hết hạn vào ngày "
                                    + vu.getVoucher().getExpiryDate()
                                    + ". Hãy sử dụng ngay để tránh lãng phí.")
                            .build()
            );

            log.info("Notify expiring soon → User {}, Voucher {}", vu.getUserId(), vu.getVoucher().getCode());
        });

        return voucherUsers.size();
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
    for (var vu : expiredVoucherUsers) {
        notificationProducer.sendNotificationMessage(
                NotificationEvent.builder()
                        .userId(vu.getUserId())
                        .title("Voucher đã hết hạn")
                        .message("Voucher " + vu.getVoucher().getName()
                                + " của bạn đã hết hạn vào ngày "
                                + vu.getVoucher().getExpiryDate()
                                + ". Hãy kiểm tra các ưu đãi khác trên ứng dụng của chúng tôi.")
                        .build()
        );
    }
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
