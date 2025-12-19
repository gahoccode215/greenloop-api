package com.greenloop.reward.service;

import com.greenloop.reward.dto.request.VoucherUsedRequest;

public interface VoucherInternalService {

  void markVoucherAsUsed(VoucherUsedRequest request);
}
