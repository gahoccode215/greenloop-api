package com.greenloop.reward.config;

import com.greenloop.reward.entity.*;
import com.greenloop.reward.enums.*;
import com.greenloop.reward.repository.EcoPointRuleRepository;
import com.greenloop.reward.repository.EcoPointUserRepository;
import com.greenloop.reward.repository.VoucherCampaignRepository;
import com.greenloop.reward.repository.VoucherUserRepository;
import com.greenloop.reward.service.CacheService;
import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataInit implements CommandLineRunner {
  private final EcoPointRuleRepository ecoPointRuleRepository;
  private final VoucherCampaignRepository voucherCampaignRepository;
  private final EcoPointUserRepository ecoPointUserRepository;
  private final VoucherUserRepository voucherUserRepository;
  private final CacheService cacheService;

  @Override
  public void run(String... args) throws Exception {
    log.info("Reward service data initialization started.");
    initEcoPointRules();
    initVoucherCampaigns();
    initTestCustomers();
    initTestCustomerVouchers();
    log.info("Reward service data initialization completed.");
  }

  private void initEcoPointRules() {
    if (ecoPointRuleRepository.count() > 0) {
      log.info("EcoPoint rules already exist. Skipping initialization.");
      return;
    }

    log.info("Initializing EcoPoint rules...");

    List<EcoPointRule> rules =
        List.of(
            // DONATION Rules - Category 1 (Áo thun)
            EcoPointRule.builder()
                .code("DONATE_TSHIRT")
                .name("Quyên Góp Áo Thun")
                .description("Điểm thưởng khi quyên góp áo thun cũ tại sự kiện thu gom")
                .actionType(EcoActionType.DONATION)
                .minPoints(20)
                .maxPoints(100)
                .categoryId(1L)
                .build(),

            // DONATION Rules - Category 2 (Quần jean)
            EcoPointRule.builder()
                .code("DONATE_JEANS")
                .name("Quyên Góp Quần Jean")
                .description("Điểm thưởng khi quyên góp quần jean cũ tại sự kiện thu gom")
                .actionType(EcoActionType.DONATION)
                .minPoints(30)
                .maxPoints(150)
                .categoryId(2L)
                .build(),

            // RESALE Rules - Category 1 (Áo thun)
            EcoPointRule.builder()
                .code("RESALE_TSHIRT")
                .name("Bán Lại Áo Thun")
                .description("Điểm thưởng khi bán lại áo thun cũ qua hệ thống")
                .actionType(EcoActionType.RESALE)
                .minPoints(50)
                .maxPoints(300)
                .categoryId(1L)
                .build(),

            // RESALE Rules - Category 2 (Quần jean)
            EcoPointRule.builder()
                .code("RESALE_JEANS")
                .name("Bán Lại Quần Jean")
                .description("Điểm thưởng khi bán lại quần jean cũ qua hệ thống")
                .actionType(EcoActionType.RESALE)
                .minPoints(60)
                .maxPoints(350)
                .categoryId(2L)
                .build(),

            // CHECK_IN Rule - Checkin tại sự kiện
            EcoPointRule.builder()
                .code("EVENT_CHECKIN")
                .name("Check-in Tại Sự Kiện")
                .description("Điểm thưởng khi check-in tham gia sự kiện thu gom quần áo cũ")
                .actionType(EcoActionType.CHECK_IN)
                .minPoints(50)
                .maxPoints(100)
                .categoryId(null)
                .build());

    ecoPointRuleRepository.saveAll(rules);
    log.info("Initialized {} EcoPoint rules", rules.size());

    // Cache rules
    try {
      rules.forEach(
          rule -> {
            String cacheKey =
                rule.getCategoryId() != null
                    ? "eco_point_rule_" + rule.getActionType() + "_" + rule.getCategoryId()
                    : "eco_point_rule_" + rule.getActionType();
            cacheService.store(cacheKey, rule);
          });
      log.info("EcoPoint rules cached successfully");
    } catch (Exception e) {
      log.error("Error caching EcoPoint rules: {}", e.getMessage());
    }
  }

  private void initVoucherCampaigns() {
    if (voucherCampaignRepository.count() > 0) {
      log.info("Voucher campaigns already exist. Skipping initialization.");
      return;
    }

    log.info("Initializing voucher campaigns...");

    List<VoucherCampaign> campaigns =
        List.of(
            createWelcomeCampaign(),
            createGreenShopperCampaign(),
            createEcoWarriorCampaign(),
            createMonthlySpecialCampaign());

    voucherCampaignRepository.saveAll(campaigns);
    log.info(
        "Initialized {} voucher campaigns with {} total vouchers",
        campaigns.size(),
        campaigns.stream().mapToInt(c -> c.getVouchers().size()).sum());
  }

  private void initTestCustomers() {
    log.info("Initializing test customers...");

    // Customer IDs: 3, 4, 5 from User Service DataInit
    List<Long> customerIds = List.of(3L, 4L, 5L);

    for (Long customerId : customerIds) {
      if (ecoPointUserRepository.findByUserId(customerId).isEmpty()) {
        EcoPointUser customer =
            EcoPointUser.builder()
                .userId(customerId)
                .totalPoints(10000)
                .lifetimePoints(10000)
                .status(EcoPointStatus.ACTIVE)
                .build();

        ecoPointUserRepository.save(customer);
        log.info("Created EcoPointUser for customer ID: {} with 10,000 points", customerId);
      }
    }
  }

  private void initTestCustomerVouchers() {
    log.info("Assigning vouchers to test customers...");

    List<Long> customerIds = List.of(3L, 4L, 5L);
    List<VoucherCampaign> campaigns = voucherCampaignRepository.findAllWithVouchers();

    for (Long customerId : customerIds) {
      if (!voucherUserRepository.findByUserId(customerId).isEmpty()) {
        log.info("Customer {} already has vouchers. Skipping.", customerId);
        continue;
      }

      List<VoucherUser> voucherUsers = new ArrayList<>();

      // Assign 2 vouchers from each campaign to each customer
      for (VoucherCampaign campaign : campaigns) {
        List<Voucher> vouchers = campaign.getVouchers();
        for (int i = 0; i < Math.min(2, vouchers.size()); i++) {
          Voucher voucher = vouchers.get(i);

          VoucherUser voucherUser =
              VoucherUser.builder()
                  .voucher(voucher)
                  .userId(customerId)
                  .quantity(1)
                  .assignedAt(LocalDateTime.now())
                  .status(VoucherUserStatus.AVAILABLE)
                  .build();

          voucherUsers.add(voucherUser);
        }
      }

      voucherUserRepository.saveAll(voucherUsers);
      log.info("Assigned {} vouchers to customer {}", voucherUsers.size(), customerId);
    }
  }

  // ==================== CAMPAIGN BUILDERS ====================

  private VoucherCampaign createWelcomeCampaign() {
    VoucherCampaign campaign =
        VoucherCampaign.builder()
            .name("Chào Mừng Thành Viên Mới")
            .description("Voucher chào mừng dành cho người dùng mới đăng ký GreenLoop")
            .startDate(LocalDateTime.now())
            .endDate(LocalDateTime.now().plusMonths(12))
            .build();

    campaign.addVoucher(
        createVoucher(
            "WELCOME10",
            "Giảm 10% Đơn Đầu",
            "Giảm 10% cho đơn hàng đầu tiên trên 100,000đ",
            VoucherType.PERCENT,
            50,
            new BigDecimal("10"),
            new BigDecimal("100000"),
            new BigDecimal("50000"),
            200));

    campaign.addVoucher(
        createVoucher(
            "FREESHIP1ST",
            "Miễn Phí Ship Đơn Đầu",
            "Miễn phí vận chuyển cho đơn hàng đầu tiên",
            VoucherType.FREESHIP,
            30,
            new BigDecimal("25000"),
            new BigDecimal("0"),
            new BigDecimal("25000"),
            150));

    campaign.addVoucher(
        createVoucher(
            "NEW50K",
            "Giảm 50K Đơn Đầu",
            "Giảm ngay 50,000đ cho đơn hàng từ 200,000đ",
            VoucherType.AMOUNT,
            100,
            new BigDecimal("50000"),
            new BigDecimal("200000"),
            new BigDecimal("50000"),
            100));

    return campaign;
  }

  private VoucherCampaign createGreenShopperCampaign() {
    VoucherCampaign campaign =
        VoucherCampaign.builder()
            .name("Người Mua Sắm Xanh")
            .description("Ưu đãi dành cho khách hàng thường xuyên mua sắm thời trang tái chế")
            .startDate(LocalDateTime.now())
            .endDate(LocalDateTime.now().plusMonths(6))
            .build();

    campaign.addVoucher(
        createVoucher(
            "GREEN15",
            "Giảm 15% Mua Sắm Xanh",
            "Giảm 15% khi mua sản phẩm thời trang tái chế",
            VoucherType.PERCENT,
            150,
            new BigDecimal("15"),
            new BigDecimal("150000"),
            new BigDecimal("75000"),
            180));

    campaign.addVoucher(
        createVoucher(
            "GREEN100K",
            "Giảm 100K Cho Người Xanh",
            "Giảm 100,000đ cho đơn hàng từ 400,000đ",
            VoucherType.AMOUNT,
            250,
            new BigDecimal("100000"),
            new BigDecimal("400000"),
            new BigDecimal("100000"),
            120));

    campaign.addVoucher(
        createVoucher(
            "GREENSHIP",
            "Free Ship Xanh",
            "Miễn phí vận chuyển cho đơn hàng thời trang tái chế",
            VoucherType.FREESHIP,
            80,
            new BigDecimal("30000"),
            new BigDecimal("0"),
            new BigDecimal("30000"),
            300));

    return campaign;
  }

  private VoucherCampaign createEcoWarriorCampaign() {
    VoucherCampaign campaign =
        VoucherCampaign.builder()
            .name("Chiến Binh Môi Trường")
            .description("Phần thưởng đặc biệt cho những người tích cực bảo vệ môi trường")
            .startDate(LocalDateTime.now())
            .endDate(LocalDateTime.now().plusMonths(12))
            .build();

    campaign.addVoucher(
        createVoucher(
            "ECO25",
            "Giảm 25% Chiến Binh Xanh",
            "Giảm 25% dành riêng cho người tích cực quyên góp & tái chế",
            VoucherType.PERCENT,
            500,
            new BigDecimal("25"),
            new BigDecimal("300000"),
            new BigDecimal("150000"),
            80));

    campaign.addVoucher(
        createVoucher(
            "ECO200K",
            "Giảm 200K Đại Sứ Xanh",
            "Giảm 200,000đ cho Đại sứ xanh của GreenLoop",
            VoucherType.AMOUNT,
            800,
            new BigDecimal("200000"),
            new BigDecimal("800000"),
            new BigDecimal("200000"),
            50));

    campaign.addVoucher(
        createVoucher(
            "ECOVIP",
            "Free Ship VIP Xanh",
            "Miễn phí vận chuyển không giới hạn cho Chiến binh Xanh",
            VoucherType.FREESHIP,
            400,
            new BigDecimal("35000"),
            new BigDecimal("0"),
            new BigDecimal("35000"),
            100));

    return campaign;
  }

  private VoucherCampaign createMonthlySpecialCampaign() {
    VoucherCampaign campaign =
        VoucherCampaign.builder()
            .name("Ưu Đãi Tháng 12")
            .description("Chương trình khuyến mãi đặc biệt tháng 12")
            .startDate(LocalDateTime.now())
            .endDate(LocalDateTime.now().plusMonths(1))
            .build();

    campaign.addVoucher(
        createVoucher(
            "DEC20",
            "Giảm 20% Tháng 12",
            "Giảm 20% cho tất cả sản phẩm trong tháng 12",
            VoucherType.PERCENT,
            200,
            new BigDecimal("20"),
            new BigDecimal("200000"),
            new BigDecimal("100000"),
            250));

    campaign.addVoucher(
        createVoucher(
            "DEC150K",
            "Giảm 150K Cuối Năm",
            "Giảm 150,000đ mừng cuối năm cho đơn từ 500,000đ",
            VoucherType.AMOUNT,
            350,
            new BigDecimal("150000"),
            new BigDecimal("500000"),
            new BigDecimal("150000"),
            100));

    campaign.addVoucher(
        createVoucher(
            "DECSHIP",
            "Free Ship Tháng 12",
            "Miễn phí vận chuyển suốt tháng 12",
            VoucherType.FREESHIP,
            120,
            new BigDecimal("25000"),
            new BigDecimal("0"),
            new BigDecimal("25000"),
            400));

    return campaign;
  }

  // ==================== VOUCHER BUILDER ====================

  private Voucher createVoucher(
      String code,
      String name,
      String description,
      VoucherType type,
      int pointToRedeem,
      BigDecimal value,
      BigDecimal minOrderValue,
      BigDecimal maxDiscount,
      int quantity) {

    return Voucher.builder()
        .code(code)
        .name(name)
        .description(description)
        .type(type)
        .value(value)
        .minOrderValue(minOrderValue)
        .maxDiscount(maxDiscount)
        .status(VoucherStatus.ACTIVE)
        .expiryDate(LocalDateTime.now().plusMonths(6))
        .quantity(quantity)
        .pointToRedeem(pointToRedeem)
        .build();
  }
}
