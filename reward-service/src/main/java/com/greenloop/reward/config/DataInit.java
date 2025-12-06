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
        log.info("Data initialization started.");
        initEcoPointRules();
        initVoucherCampaigns();
        initTestCustomer();
        initTestCustomerVouchers();
        log.info("Data initialization completed.");
    }

    private void initEcoPointRules() {
        long count = ecoPointRuleRepository.count();
        if (count == 0) {
            log.info("No eco point rules found. Initializing default data.");

            List<EcoPointRule> rules =
                    List.of(
                            // DONATION Rules
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
                                    .code("DONATE_PREMIUM")
                                    .name("Premium Item Donation")
                                    .description("Award extra points for donating high-quality items")
                                    .actionType(EcoActionType.DONATION)
                                    .minPoints(50)
                                    .maxPoints(500)
                                    .categoryId(1L)
                                    .build(),

                            // RESALE Rules
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
                                    .minPoints(100)
                                    .maxPoints(600)
                                    .categoryId(1L)
                                    .build(),
                            EcoPointRule.builder()
                                    .code("RESALE_FAST")
                                    .name("Fast Resale")
                                    .description("Bonus points for items sold within 7 days")
                                    .actionType(EcoActionType.RESALE)
                                    .minPoints(20)
                                    .maxPoints(100)
                                    .categoryId(3L)
                                    .build(),

                            // CHECK_IN Rules
                            EcoPointRule.builder()
                                    .code("DAILY_CHECKIN")
                                    .name("Daily Check-in")
                                    .description("Award points for daily platform engagement")
                                    .actionType(EcoActionType.CHECK_IN)
                                    .minPoints(5)
                                    .maxPoints(20)
                                    .categoryId(4L)
                                    .build(),
                            EcoPointRule.builder()
                                    .code("WEEKLY_CHECKIN")
                                    .name("Weekly Check-in Streak")
                                    .description("Bonus points for 7 consecutive days check-in")
                                    .actionType(EcoActionType.CHECK_IN)
                                    .minPoints(50)
                                    .maxPoints(100)
                                    .categoryId(4L)
                                    .build(),
                            EcoPointRule.builder()
                                    .code("MONTHLY_CHECKIN")
                                    .name("Monthly Check-in Champion")
                                    .description("Special reward for 30 consecutive days check-in")
                                    .actionType(EcoActionType.CHECK_IN)
                                    .minPoints(200)
                                    .maxPoints(500)
                                    .categoryId(4L)
                                    .build());

            ecoPointRuleRepository.saveAll(rules);
            log.info("Default eco point rules inserted: {} rules", rules.size());

            try {
                List<EcoPointRule> savedRules = ecoPointRuleRepository.findAll();
                for (EcoPointRule rule : savedRules) {
                    cacheService.store("eco_point_rule_" + rule.getId(), rule);
                }
                log.info("Eco point rules cached successfully.");
            } catch (Exception e) {
                log.error("Error caching eco point rules: {}", e.getMessage());
            }
        } else {
            log.info("Eco point rules already exist. Skipping data initialization.");
        }
    }

    private void initVoucherCampaigns() {
        long countCampaign = voucherCampaignRepository.count();

        if (countCampaign == 0) {
            log.info("No campaigns found. Creating sample campaigns...");

            List<VoucherCampaign> campaigns =
                    List.of(
                            createNewUserCampaign(),
                            createSeasonalCampaign(),
                            createLoyaltyCampaign(),
                            createFlashSaleCampaign(),
                            createEcoWarriorCampaign());

            voucherCampaignRepository.saveAll(campaigns);
            log.info("Sample voucher campaigns created: {} campaigns", campaigns.size());
        } else {
            log.info("Voucher campaigns already exist. Skipping initialization.");
        }
    }

    private void initTestCustomer() {
        if (ecoPointUserRepository.findByUserId(1L).isPresent()) {
            log.info("Test customer (userId=1) already exists. Skipping creation.");
            return;
        }

        log.info("Creating test customer with 50,000 eco points...");

        EcoPointUser testCustomer = EcoPointUser.builder()
                .userId(1L)
                .totalPoints(50000)
                .lifetimePoints(50000)
                .status(EcoPointStatus.ACTIVE)
                .build();

        ecoPointUserRepository.save(testCustomer);

        log.info("Test customer created successfully: userId=1, totalPoints=50000");
    }

    private void initTestCustomerVouchers() {
        // Check if vouchers already assigned
        if (!voucherUserRepository.findByUserId(1L).isEmpty()) {
            log.info("Vouchers already assigned to customer 1. Skipping voucher assignment.");
            return;
        }

        log.info("Assigning vouchers to test customer (userId=1)...");

        List<VoucherCampaign> campaigns = voucherCampaignRepository.findAllWithVouchers();
        List<VoucherUser> voucherUsers = new ArrayList<>();

        for (VoucherCampaign campaign : campaigns) {
            for (Voucher voucher : campaign.getVouchers()) {
                VoucherUser voucherUser = VoucherUser.builder()
                        .voucher(voucher)
                        .userId(1L)
                        .quantity(1)
                        .assignedAt(LocalDateTime.now())
                        .status(VoucherUserStatus.AVAILABLE)
                        .build();

                voucherUsers.add(voucherUser);
            }
        }

        voucherUserRepository.saveAll(voucherUsers);

        log.info("Assigned {} vouchers to customer 1", voucherUsers.size());
    }

    // ==================== CAMPAIGN BUILDERS ====================

    private VoucherCampaign createNewUserCampaign() {
        VoucherCampaign campaign =
                VoucherCampaign.builder()
                        .name("Welcome New Users Campaign")
                        .description("Special vouchers for newly registered users")
                        .startDate(LocalDateTime.now())
                        .endDate(LocalDateTime.now().plusMonths(6))
                        .build();

        campaign.addVoucher(
                createVoucher(
                        "WELCOME10",
                        "Welcome 10% OFF",
                        "Get 10% discount on your first purchase",
                        VoucherType.PERCENT,
                        50,
                        new BigDecimal("10"),
                        new BigDecimal("50000"),
                        new BigDecimal("30000"),
                        200));

        campaign.addVoucher(
                createVoucher(
                        "FREESHIP1ST",
                        "First Order Free Shipping",
                        "Free shipping for your first order",
                        VoucherType.FREESHIP,
                        30,
                        new BigDecimal("30000"),
                        new BigDecimal("0"),
                        new BigDecimal("30000"),
                        150));

        campaign.addVoucher(
                createVoucher(
                        "NEWUSER50K",
                        "New User 50K OFF",
                        "Get 50,000đ discount on orders above 200,000đ",
                        VoucherType.AMOUNT,
                        100,
                        new BigDecimal("50000"),
                        new BigDecimal("200000"),
                        new BigDecimal("50000"),
                        100));

        return campaign;
    }

    private VoucherCampaign createSeasonalCampaign() {
        VoucherCampaign campaign =
                VoucherCampaign.builder()
                        .name("Seasonal Sale Campaign")
                        .description("Special discounts for holiday and seasonal events")
                        .startDate(LocalDateTime.now())
                        .endDate(LocalDateTime.now().plusMonths(3))
                        .build();

        campaign.addVoucher(
                createVoucher(
                        "SUMMER20",
                        "Summer Sale 20% OFF",
                        "20% discount for summer shopping",
                        VoucherType.PERCENT,
                        150,
                        new BigDecimal("20"),
                        new BigDecimal("100000"),
                        new BigDecimal("100000"),
                        300));

        campaign.addVoucher(
                createVoucher(
                        "HOLIDAY100K",
                        "Holiday Special 100K OFF",
                        "Save 100,000đ on orders above 500,000đ",
                        VoucherType.AMOUNT,
                        250,
                        new BigDecimal("100000"),
                        new BigDecimal("500000"),
                        new BigDecimal("100000"),
                        150));

        campaign.addVoucher(
                createVoucher(
                        "FREESHIP-SEASON",
                        "Seasonal Free Shipping",
                        "Free shipping for all orders",
                        VoucherType.FREESHIP,
                        80,
                        new BigDecimal("25000"),
                        new BigDecimal("0"),
                        new BigDecimal("25000"),
                        500));

        return campaign;
    }

    private VoucherCampaign createLoyaltyCampaign() {
        VoucherCampaign campaign =
                VoucherCampaign.builder()
                        .name("Loyalty Rewards Campaign")
                        .description("Exclusive rewards for loyal and active customers")
                        .startDate(LocalDateTime.now())
                        .endDate(LocalDateTime.now().plusMonths(12))
                        .build();

        campaign.addVoucher(
                createVoucher(
                        "VIP15",
                        "VIP Member 15% OFF",
                        "Exclusive 15% discount for VIP members",
                        VoucherType.PERCENT,
                        300,
                        new BigDecimal("15"),
                        new BigDecimal("150000"),
                        new BigDecimal("75000"),
                        100));

        campaign.addVoucher(
                createVoucher(
                        "LOYAL200K",
                        "Loyalty 200K OFF",
                        "200,000đ discount for loyal customers",
                        VoucherType.AMOUNT,
                        500,
                        new BigDecimal("200000"),
                        new BigDecimal("1000000"),
                        new BigDecimal("200000"),
                        50));

        campaign.addVoucher(
                createVoucher(
                        "FREESHIP-VIP",
                        "VIP Free Shipping Unlimited",
                        "Free shipping for VIP members - no minimum",
                        VoucherType.FREESHIP,
                        200,
                        new BigDecimal("30000"),
                        new BigDecimal("0"),
                        new BigDecimal("30000"),
                        200));

        return campaign;
    }

    private VoucherCampaign createFlashSaleCampaign() {
        VoucherCampaign campaign =
                VoucherCampaign.builder()
                        .name("Flash Sale Campaign")
                        .description("Limited time flash sale vouchers")
                        .startDate(LocalDateTime.now())
                        .endDate(LocalDateTime.now().plusDays(7))
                        .build();

        campaign.addVoucher(
                createVoucher(
                        "FLASH30",
                        "Flash Sale 30% OFF",
                        "Massive 30% discount - Limited quantity",
                        VoucherType.PERCENT,
                        350,
                        new BigDecimal("30"),
                        new BigDecimal("200000"),
                        new BigDecimal("150000"),
                        50));

        campaign.addVoucher(
                createVoucher(
                        "FLASH150K",
                        "Flash 150K OFF",
                        "Save 150,000đ instantly",
                        VoucherType.AMOUNT,
                        400,
                        new BigDecimal("150000"),
                        new BigDecimal("600000"),
                        new BigDecimal("150000"),
                        30));

        campaign.addVoucher(
                createVoucher(
                        "FLASHSHIP",
                        "Flash Free Shipping",
                        "Free shipping during flash sale hours",
                        VoucherType.FREESHIP,
                        120,
                        new BigDecimal("20000"),
                        new BigDecimal("0"),
                        new BigDecimal("20000"),
                        100));

        return campaign;
    }

    private VoucherCampaign createEcoWarriorCampaign() {
        VoucherCampaign campaign =
                VoucherCampaign.builder()
                        .name("Eco Warrior Rewards Campaign")
                        .description("Special vouchers for environmentally conscious users")
                        .startDate(LocalDateTime.now())
                        .endDate(LocalDateTime.now().plusMonths(6))
                        .build();

        campaign.addVoucher(
                createVoucher(
                        "ECO25",
                        "Eco Champion 25% OFF",
                        "25% discount for eco-friendly purchases",
                        VoucherType.PERCENT,
                        600,
                        new BigDecimal("25"),
                        new BigDecimal("300000"),
                        new BigDecimal("125000"),
                        80));

        campaign.addVoucher(
                createVoucher(
                        "GREENSAVE",
                        "Green Saver 100K OFF",
                        "100,000đ off on eco-certified products",
                        VoucherType.AMOUNT,
                        800,
                        new BigDecimal("100000"),
                        new BigDecimal("400000"),
                        new BigDecimal("100000"),
                        60));

        campaign.addVoucher(
                createVoucher(
                        "ECOSHIP",
                        "Eco-Friendly Free Shipping",
                        "Free green shipping for eco warriors",
                        VoucherType.FREESHIP,
                        400,
                        new BigDecimal("35000"),
                        new BigDecimal("0"),
                        new BigDecimal("35000"),
                        150));

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
