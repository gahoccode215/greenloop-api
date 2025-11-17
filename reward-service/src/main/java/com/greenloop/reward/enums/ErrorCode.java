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

  INVALID_ECO_POINT_TRANSACTION("ECO_004", "Invalid eco point transaction", HttpStatus.BAD_REQUEST);

  private final String code;
  private final String message;
  private final HttpStatus status;
}
