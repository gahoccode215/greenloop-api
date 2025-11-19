package com.greenloop.reward.repository;

import com.greenloop.reward.entity.VoucherCampaign;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface VoucherCampaignRepository
    extends JpaRepository<VoucherCampaign, Long>, JpaSpecificationExecutor<VoucherCampaign> {}
