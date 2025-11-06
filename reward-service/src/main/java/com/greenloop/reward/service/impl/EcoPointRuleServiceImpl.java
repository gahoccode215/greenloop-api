package com.greenloop.reward.service.impl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.greenloop.reward.dto.request.EcoPointRuleFilterRequest;
import com.greenloop.reward.dto.request.EcoPointRuleRequest;
import com.greenloop.reward.dto.response.EcoPointResponse;
import com.greenloop.reward.entity.EcoPointRule;
import com.greenloop.reward.enums.ErrorCode;
import com.greenloop.reward.exception.BusinessException;
import com.greenloop.reward.repository.EcoPointRuleRepository;
import com.greenloop.reward.service.CacheService;
import com.greenloop.reward.service.EcoPointRuleService;
import java.util.List;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class EcoPointRuleServiceImpl implements EcoPointRuleService {

  private final EcoPointRuleRepository ecoPointRuleRepository;
  private final CacheService cacheService;

  @Override
  public Long createEcoPointRules(EcoPointRuleRequest request) {
    log.info("Creating eco point rules request");
    Long userId = getCurrentUserId();
    log.info("Current user ID: {}", userId);
    boolean existsByCode = ecoPointRuleRepository.existsByCode(request.getCode());
    if (existsByCode) {
      log.warn("Eco point rule with code {} already exists", request.getCode());
      throw new BusinessException(ErrorCode.ECO_POINT_RULE_ALREADY_EXISTS);
    }

    boolean ruleExists =
        ecoPointRuleRepository.existsByActionTypeAndCategoryId(
            request.getActionType(), request.getCategoryId());
    if (ruleExists) {
      log.warn(
          "Eco point rule with action type {} and category ID {} already exists",
          request.getActionType(),
          request.getCategoryId());
      throw new BusinessException(ErrorCode.ECO_POINT_RULE_FOR_ACTION_AND_CATEGORY_EXISTS);
    }

    EcoPointRule ecoPointRule =
        EcoPointRule.builder()
            .code(request.getCode())
            .name(request.getName())
            .description(request.getDescription())
            .actionType(request.getActionType())
            .minPoints(request.getMinPoints())
            .maxPoints(request.getMaxPoints())
            .categoryId(request.getCategoryId())
            .build();
    ecoPointRule.createdBy(userId);
    ecoPointRule = ecoPointRuleRepository.save(ecoPointRule);
    EcoPointResponse response =
        EcoPointResponse.builder()
            .id(ecoPointRule.getId())
            .categoryId(ecoPointRule.getCategoryId())
            .code(ecoPointRule.getCode())
            .name(ecoPointRule.getName())
            .description(ecoPointRule.getDescription())
            .actionType(ecoPointRule.getActionType())
            .minPoints(ecoPointRule.getMinPoints())
            .maxPoints(ecoPointRule.getMaxPoints())
            .isActive(ecoPointRule.isActive())
            .build();
    cacheService.store(keyBuilder(ecoPointRule), response);
    log.info("Eco point rule with code {} created successfully", request.getCode());
    return ecoPointRule.getId();
  }

  public List<EcoPointResponse> getAllEcoPointRules(EcoPointRuleFilterRequest filter) {
    String redisKey = "eco_point_rule_" + filter.getActionType() + "_" + filter.getCategoryId();
    List<EcoPointResponse> cached =
        cacheService.get(redisKey, new TypeReference<List<EcoPointResponse>>() {});
    if (cached != null && !cached.isEmpty()) {
      return applyFilter(cached, filter);
    }

    List<EcoPointRule> rules =
        ecoPointRuleRepository.findAllByFilter(
            filter.getActionType(), filter.getCode(), filter.getName());

    List<EcoPointResponse> responses =
        rules.stream().map(this::mapToResponse).collect(Collectors.toList());
    return responses;
  }

  public void updateEcoPointRule(Long id, EcoPointRuleRequest request) {
    log.info("Updating eco point rule with ID: {}", id);
    EcoPointRule rule =
        ecoPointRuleRepository
            .findById(id)
            .orElseThrow(() -> new BusinessException(ErrorCode.ECO_POINT_RULE_NOT_FOUND));
    if (!rule.getCode().equals(request.getCode())) {
      boolean existsByCode = ecoPointRuleRepository.existsByCode(request.getCode());
      if (existsByCode) {
        log.warn("Eco point rule with code {} already exists", request.getCode());
        throw new BusinessException(ErrorCode.ECO_POINT_RULE_ALREADY_EXISTS);
      }
    }
    rule.setName(request.getName());
    rule.setDescription(request.getDescription());
    rule.setMinPoints(request.getMinPoints());
    rule.setMaxPoints(request.getMaxPoints());
    rule.setCategoryId(request.getCategoryId());
    rule.setCode(request.getCode());
    rule.setActionType(request.getActionType());
    rule.updatedBy(getCurrentUserId());

    ecoPointRuleRepository.save(rule);

    cacheService.remove(keyBuilder(rule));
    cacheService.store(keyBuilder(rule), mapToResponse(rule));
    log.info("Eco point rule with ID: {} updated successfully", id);
  }

  public void changeStatus(Long id) {
    EcoPointRule rule =
        ecoPointRuleRepository
            .findById(id)
            .orElseThrow(() -> new BusinessException(ErrorCode.ECO_POINT_RULE_NOT_FOUND));

    rule.setActive(!rule.isActive());
    rule.updatedBy(getCurrentUserId());
    ecoPointRuleRepository.save(rule);

    cacheService.remove(keyBuilder(rule));
    cacheService.store(keyBuilder(rule), mapToResponse(rule));
    log.info("Eco point rule with ID: {} status changed successfully", id);
  }

  private List<EcoPointResponse> applyFilter(
      List<EcoPointResponse> list, EcoPointRuleFilterRequest filter) {
    return list.stream()
        .filter(rule -> filter.getCode() == null || rule.getCode().contains(filter.getCode()))
        .filter(rule -> filter.getName() == null || rule.getName().contains(filter.getName()))
        .collect(Collectors.toList());
  }

  private EcoPointResponse mapToResponse(EcoPointRule rule) {
    return EcoPointResponse.builder()
        .id(rule.getId())
        .categoryId(rule.getCategoryId())
        .code(rule.getCode())
        .name(rule.getName())
        .description(rule.getDescription())
        .actionType(rule.getActionType())
        .minPoints(rule.getMinPoints())
        .maxPoints(rule.getMaxPoints())
        .isActive(rule.isActive())
        .build();
  }

  private Long getCurrentUserId() {
    return Long.valueOf(
        SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
  }

  private String keyBuilder(EcoPointRule request) {
    return "eco_point_rule_" + request.getActionType() + "_" + request.getCategoryId();
  }
}
