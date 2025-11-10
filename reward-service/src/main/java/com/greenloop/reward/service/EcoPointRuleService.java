package com.greenloop.reward.service;

import com.greenloop.reward.dto.request.EcoPointRuleFilterRequest;
import com.greenloop.reward.dto.request.EcoPointRuleRequest;
import com.greenloop.reward.dto.response.EcoPointResponse;

import java.util.List;

public interface EcoPointRuleService {
    Long createEcoPointRules(EcoPointRuleRequest request);

    List<EcoPointResponse> getAllEcoPointRules(EcoPointRuleFilterRequest filter);

    EcoPointResponse getEcoPointInfo(EcoPointRuleRequest request);

    void updateEcoPointRule(Long id, EcoPointRuleRequest request);

    void changeStatus(Long id);
}
