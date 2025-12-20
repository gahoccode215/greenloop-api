package com.greenloop.reward.service;

import com.greenloop.reward.dto.request.EcoPointInfoRequest;
import com.greenloop.reward.dto.request.EcoPointRuleFilterRequest;
import com.greenloop.reward.dto.request.EcoPointRuleRequest;
import com.greenloop.reward.dto.response.EcoPointResponse;
import com.greenloop.reward.dto.response.EcoPointRuleExportDTO;
import com.greenloop.reward.enums.EcoActionType;

import java.util.List;

public interface EcoPointRuleService {
  Long createEcoPointRules(EcoPointRuleRequest request);

  List<EcoPointResponse> getAllEcoPointRules(EcoPointRuleFilterRequest filter);

  EcoPointResponse getEcoPointInfo(EcoPointInfoRequest request);

  void updateEcoPointRule(Long id, EcoPointRuleRequest request);

  void changeStatus(Long id);
}
