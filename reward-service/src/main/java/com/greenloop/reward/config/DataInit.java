package com.greenloop.reward.config;

import com.greenloop.reward.entity.EcoPointRule;
import com.greenloop.reward.entity.Voucher;
import com.greenloop.reward.entity.VoucherCampaign;
import com.greenloop.reward.enums.EcoActionType;
import com.greenloop.reward.enums.VoucherStatus;
import com.greenloop.reward.enums.VoucherType;
import com.greenloop.reward.repository.EcoPointRuleRepository;
import com.greenloop.reward.repository.VoucherCampaignRepository;
import com.greenloop.reward.service.CacheService;
import java.math.BigDecimal;
import java.time.LocalDateTime;
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
  private final CacheService cacheService;

  @Override
  public void run(String... args) throws Exception {
    log.info("Data initialization started.");
    long count = ecoPointRuleRepository.count();
    if (count == 0) {
      log.info("No eco point rules found. Initializing default data.");
      List<EcoPointRule> rules =
          List.of(
              EcoPointRule.builder()
                  .code("DONATE_ITEM")
                  .name("Donation Item")
                  .description("Award points when users donate reusable items")
                  .actionType(EcoActionType.DONATION)
                  .minPoints(10)
                  .maxPoints(300)
                  .categoryId(1L)
                  .build(),
              EcoPointRule.builder()
                  .code("DONATE_BULK")
                  .name("Bulk Donation")
                  .description("Award points for donating a bulk of items")
                  .actionType(EcoActionType.DONATION)
                  .minPoints(30)
                  .maxPoints(700)
                  .categoryId(2L)
                  .build(),
              EcoPointRule.builder()
                  .code("RESALE_ITEM")
                  .name("Resale Item")
                  .description("Award points when a user resells used items through platform")
                  .actionType(EcoActionType.RESALE)
                  .minPoints(50)
                  .maxPoints(250)
                  .categoryId(2L)
                  .build(),
              EcoPointRule.builder()
                  .code("RESALE_PREMIUM")
                  .name("Premium Resale")
                  .description("Award points for reselling high-value or verified items")
                  .actionType(EcoActionType.RESALE)
                  .minPoints(20)
                  .maxPoints(60)
                  .categoryId(1L)
                  .build());

      ecoPointRuleRepository.saveAll(rules);
      log.info("Default eco point rules inserted.");
      try {
        List<EcoPointRule> savedRules = ecoPointRuleRepository.findAll();
        for (EcoPointRule rule : savedRules) {
          cacheService.store("eco_point_rule_" + rule.getId(), rule);
        }
        log.info("Eco point rules cached.");
      } catch (Exception e) {
        log.error("Error caching eco point rules: {}", e.getMessage());
      }

    } else {
      log.info("Eco point rules already exist. Skipping data initialization.");
    }
    long countCampaign = voucherCampaignRepository.count();

    if (countCampaign == 0) {
      log.info("No campaigns found. Creating default sample campaigns...");

      List<VoucherCampaign> campaigns =
          List.of(
              createCampaign("New User Campaign", "Campaign for new registered users", 1),
              createCampaign("Holiday Sale Campaign", "Discounts for holiday events", 2),
              createCampaign(
                  "Loyalty Rewards Campaign", "Special vouchers for loyal customers", 3));

      voucherCampaignRepository.saveAll(campaigns);
    } else {
      log.info("Voucher campaigns already exist. Skipping initialization.");
    }

    log.info("Sample voucher campaigns and vouchers created successfully.");
    log.info("Data initialization completed.");
  }

  private VoucherCampaign createCampaign(String name, String description, int monthOffset) {
    VoucherCampaign campaign =
        VoucherCampaign.builder()
            .name(name)
            .description(description)
            .startDate(LocalDateTime.now())
            .endDate(LocalDateTime.now().plusMonths(monthOffset))
            .build();

    campaign.addVoucher(
        createVoucher(
            "DISCOUNT10-" + monthOffset,
            "10% OFF",
            100,
            new BigDecimal("0.10"),
            new BigDecimal("100000"),
            new BigDecimal("50000"),
            100,
            campaign));

    campaign.addVoucher(
        createVoucher(
            "FREESHIP-" + monthOffset,
            "Free Shipping",
            50,
            BigDecimal.ZERO,
            new BigDecimal("50000"),
            new BigDecimal("30000"),
            150,
            campaign));

    campaign.addVoucher(
        createVoucher(
            "SAVE50K-" + monthOffset,
            "Save 50,000₫",
            200,
            new BigDecimal("50000"),
            new BigDecimal("200000"),
            new BigDecimal("50000"),
            80,
            campaign));

    return campaign;
  }

  private Voucher createVoucher(
      String code,
      String name,
      int pointToRedeem,
      BigDecimal value,
      BigDecimal minOrderValue,
      BigDecimal maxDiscount,
      int quantity,
      VoucherCampaign campaign) {
    return Voucher.builder()
        .code(code)
        .name(name)
        .description(name + " voucher")
        .type(VoucherType.AMOUNT)
        .value(value)
        .minOrderValue(minOrderValue)
        .maxDiscount(maxDiscount)
        .status(VoucherStatus.ACTIVE)
        .expiryDate(LocalDateTime.now().plusMonths(3))
        .quantity(quantity)
        .pointToRedeem(pointToRedeem)
        .campaign(campaign)
        .build();
  }
}
