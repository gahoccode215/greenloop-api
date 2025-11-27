package com.greenloop.reward.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {
  ECO_POINT_RULE_ALREADY_EXISTS(
      "ECO_001", "Eco point rule with the given code already exists", HttpStatus.CONFLICT),
  ECO_POINT_RULE_FOR_ACTION_AND_CATEGORY_EXISTS(
      "ECO_002",
      "Eco point rule for the given action type and category already exists",
      HttpStatus.CONFLICT),
  ECO_POINT_RULE_NOT_FOUND("ECO_003", "Eco point rule not found", HttpStatus.NOT_FOUND),

  INVALID_ECO_POINT_TRANSACTION("ECO_004", "Invalid eco point transaction", HttpStatus.BAD_REQUEST),
  INVALID_TIME_FRAME(
      "ECO_005", "Invalid time frame: end date is before start date", HttpStatus.BAD_REQUEST),

  VOUCHER_CAMPAIGN_ID_REQUIRED(
      "VCH_001", "Voucher campaign ID is required", HttpStatus.BAD_REQUEST),
  VOUCHER_NOT_FOUND("VCH_002", "Voucher not found", HttpStatus.NOT_FOUND),
  INSUFFICIENT_VOUCHER_QUANTITY(
      "VCH_003", "Insufficient voucher quantity available", HttpStatus.BAD_REQUEST),
  VOUCHER_CAMPAIGN_NOT_FOUND("VCH_004", "Voucher campaign not found", HttpStatus.NOT_FOUND),

  VOUCHER_IS_NOT_ACTIVE("VCH_005", "Voucher is not active", HttpStatus.BAD_REQUEST),
  VOUCHER_EXPIRED("VCH_006", "Voucher has expired", HttpStatus.BAD_REQUEST),
  INSUFFICIENT_ECO_POINTS(
      "VCH_007", "Insufficient eco points to redeem voucher", HttpStatus.BAD_REQUEST),
  VOUCHER_OUT_OF_STOCK("VCH_008", "Voucher is out of stock", HttpStatus.BAD_REQUEST),
  ECO_POINT_USER_NOT_FOUND("ECO_006", "Eco point user not found", HttpStatus.NOT_FOUND),

  ECO_POINT_USER_OR_VOUCHER_IS_DEACTIVATED(
      "ECO_007", "Eco point user or voucher is deactivated", HttpStatus.BAD_REQUEST);

  private final String code;
  private final String message;
  private final HttpStatus status;
}
