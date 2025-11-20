package com.greenloop.order.ghn.service.impl;

import com.greenloop.order.ghn.client.GHNClient;
import com.greenloop.order.ghn.dto.GHNProvinceDTO;
import com.greenloop.order.ghn.service.GHNService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class GHNServiceImpl implements GHNService {

    private final GHNClient ghnClient;

    @Override
    public List<GHNProvinceDTO> getAllProvinces() {
        log.info("Fetching all provinces from GHN");
        return ghnClient.getProvinces();
    }
}
