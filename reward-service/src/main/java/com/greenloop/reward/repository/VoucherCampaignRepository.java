package com.greenloop.reward.repository;

import com.greenloop.reward.entity.VoucherCampaign;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface VoucherCampaignRepository
    extends JpaRepository<VoucherCampaign, Long>, JpaSpecificationExecutor<VoucherCampaign> {
  @Query(
      "SELECT COUNT(c) FROM VoucherCampaign c WHERE c.startDate <= CURRENT_DATE AND c.endDate >= CURRENT_DATE")
  Long countActiveCampaigns();

  @Query("SELECT vc FROM VoucherCampaign vc LEFT JOIN FETCH vc.vouchers")
  List<VoucherCampaign> findAllWithVouchers();
}
