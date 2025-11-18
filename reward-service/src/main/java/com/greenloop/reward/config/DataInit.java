package com.greenloop.reward.config;

import com.greenloop.reward.entity.EcoPointRule;
import com.greenloop.reward.enums.EcoActionType;
import com.greenloop.reward.repository.EcoPointRuleRepository;
import com.greenloop.reward.service.CacheService;
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
    log.info("Data initialization completed.");
  }
}
