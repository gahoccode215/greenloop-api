package com.greenloop.reward.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {
  ECO_POINT_RULE_ALREADY_EXISTS(
      "ECO_001", "Quy tắc eco point với mã này đã tồn tại", HttpStatus.CONFLICT),

  ECO_POINT_RULE_FOR_ACTION_AND_CATEGORY_EXISTS(
      "ECO_002",
      "Quy tắc eco point cho loại hành động và danh mục này đã tồn tại",
      HttpStatus.CONFLICT),

  ECO_POINT_RULE_NOT_FOUND("ECO_003", "Không tìm thấy quy tắc eco point", HttpStatus.NOT_FOUND),

  INVALID_ECO_POINT_TRANSACTION(
      "ECO_004", "Giao dịch eco point không hợp lệ", HttpStatus.BAD_REQUEST),

  INVALID_TIME_FRAME(
      "ECO_005",
      "Khoảng thời gian không hợp lệ: ngày kết thúc trước ngày bắt đầu",
      HttpStatus.BAD_REQUEST),

  VOUCHER_CAMPAIGN_ID_REQUIRED(
      "VCH_001", "Yêu cầu cung cấp ID chiến dịch voucher", HttpStatus.BAD_REQUEST),

  VOUCHER_NOT_FOUND("VCH_002", "Không tìm thấy voucher", HttpStatus.NOT_FOUND),

  INSUFFICIENT_VOUCHER_QUANTITY("VCH_003", "Số lượng voucher không đủ", HttpStatus.BAD_REQUEST),

  VOUCHER_CAMPAIGN_NOT_FOUND("VCH_004", "Không tìm thấy chiến dịch voucher", HttpStatus.NOT_FOUND),

  VOUCHER_IS_NOT_ACTIVE("VCH_005", "Voucher không hoạt động", HttpStatus.BAD_REQUEST),

  VOUCHER_EXPIRED("VCH_006", "Voucher đã hết hạn", HttpStatus.BAD_REQUEST),

  INSUFFICIENT_ECO_POINTS("VCH_007", "Eco point không đủ để đổi voucher", HttpStatus.BAD_REQUEST),

  VOUCHER_OUT_OF_STOCK("VCH_008", "Voucher đã hết số lượng", HttpStatus.BAD_REQUEST),

  ECO_POINT_USER_NOT_FOUND(
      "ECO_006", "Không tìm thấy tài khoản eco point của người dùng", HttpStatus.NOT_FOUND),

  ECO_POINT_USER_OR_VOUCHER_IS_DEACTIVATED(
      "ECO_007", "Tài khoản eco point hoặc voucher đã bị vô hiệu hóa", HttpStatus.BAD_REQUEST),

  VOUCHER_USER_NOT_FOUND("VCH_009", "Không tìm thấy voucher người dùng", HttpStatus.NOT_FOUND),

  VOUCHER_USER_NOT_AVAILABLE(
      "VCH_010", "Voucher người dùng không khả dụng để đổi thưởng", HttpStatus.BAD_REQUEST),

  VOUCHER_USER_OUT_OF_QUANTITY(
      "VCH_011", "Voucher người dùng đã hết số lượng", HttpStatus.BAD_REQUEST),

  VOUCHER_INACTIVE("VCH_012", "Voucher không hoạt động", HttpStatus.BAD_REQUEST);

  private final String code;
  private final String message;
  private final HttpStatus status;
}
