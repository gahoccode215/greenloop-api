package com.greenloop.order.ghn.service;

import com.greenloop.order.ghn.dto.GHNDistrictDTO;
import com.greenloop.order.ghn.dto.GHNProvinceDTO;
import com.greenloop.order.ghn.dto.GHNWardDTO;

import java.util.List;

public interface GHNService {

    List<GHNProvinceDTO> getAllProvinces();

    List<GHNDistrictDTO> getDistrictsByProvinceId(Integer provinceId);

    List<GHNWardDTO> getWardsByDistrictId(Integer districtId);
}
