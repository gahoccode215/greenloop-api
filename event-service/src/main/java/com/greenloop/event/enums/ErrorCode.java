package com.greenloop.event.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {
  CONVERT_GOOGLE_PLACE_ERROR(
      "1000", "Chuyển đổi dữ liệu Google Place thất bại", HttpStatus.BAD_REQUEST),
  UPLOAD_IMAGE_ERROR("1001", "Tải lên hình ảnh thất bại", HttpStatus.INTERNAL_SERVER_ERROR),
  EVENT_NOT_FOUND("1002", "Không tìm thấy sự kiện", HttpStatus.NOT_FOUND),
  EVENT_CODE_ALREADY_EXISTS("1003", "Mã sự kiện đã tồn tại", HttpStatus.BAD_REQUEST),
  EVENT_CODE_GENERATION_ERROR("1004", "Lỗi tạo mã sự kiện", HttpStatus.INTERNAL_SERVER_ERROR),
  EVENT_CREATION_ERROR("1005", "Lỗi tạo sự kiện", HttpStatus.INTERNAL_SERVER_ERROR),
  EVENT_UPDATE_ERROR("1006", "Lỗi cập nhật sự kiện", HttpStatus.INTERNAL_SERVER_ERROR),
  EVENT_DELETION_ERROR("1007", "Lỗi xóa sự kiện", HttpStatus.INTERNAL_SERVER_ERROR),
  EVENT_STATUS_UPDATE_ERROR(
      "1008", "Lỗi cập nhật trạng thái sự kiện", HttpStatus.INTERNAL_SERVER_ERROR),
  EVENT_IMAGE_UPLOAD_ERROR(
      "1009", "Lỗi tải lên hình ảnh sự kiện", HttpStatus.INTERNAL_SERVER_ERROR),
  EVENT_IMAGE_DELETION_ERROR("1010", "Lỗi xóa hình ảnh sự kiện", HttpStatus.INTERNAL_SERVER_ERROR),
  EVENT_LOCATION_UPDATE_ERROR(
      "1011", "Lỗi cập nhật địa điểm sự kiện", HttpStatus.INTERNAL_SERVER_ERROR),
  EVENT_START_TIME_PAST(
      "1012", "Thời gian bắt đầu sự kiện không được ở quá khứ", HttpStatus.BAD_REQUEST),
  EVENT_END_TIME_PAST(
      "1013", "Thời gian kết thúc sự kiện không được ở quá khứ", HttpStatus.BAD_REQUEST),
  EVENT_END_TIME_BEFORE_START(
      "1014", "Thời gian kết thúc không thể trước thời gian bắt đầu", HttpStatus.BAD_REQUEST),
  EVENT_LOCATION_NOT_FOUND("1015", "Không tìm thấy địa điểm sự kiện", HttpStatus.NOT_FOUND),
  INVALID_EVENT_STATUS("1016", "Trạng thái sự kiện không hợp lệ", HttpStatus.BAD_REQUEST),

  // Event Staff Assignment Errors
  STAFF_ALREADY_ASSIGNED(
      "2000", "Nhân viên đã được phân công cho sự kiện này", HttpStatus.BAD_REQUEST),
  STORE_MANAGER_ALREADY_ASSIGNED(
      "2001", "Quản lý cửa hàng đã được phân công cho sự kiện này", HttpStatus.BAD_REQUEST),
  INVALID_ROLE("2002", "Vai trò phân công không hợp lệ", HttpStatus.BAD_REQUEST),
  STAFF_EVENT_TIME_CONFLICT(
      "2003", "Nhân viên có xung đột thời gian với một sự kiện khác", HttpStatus.BAD_REQUEST),

  // User Related Errors
  USER_NOT_FOUND("3000", "Không tìm thấy người dùng", HttpStatus.NOT_FOUND),
  ALREADY_REGISTERED("3001", "Người dùng đã đăng ký sự kiện này", HttpStatus.BAD_REQUEST),
  REGISTRATION_NOT_FOUND("3002", "Không tìm thấy thông tin đăng ký sự kiện", HttpStatus.NOT_FOUND),
  UNAUTHORIZED_ACCESS("3003", "Truy cập không được phép", HttpStatus.UNAUTHORIZED),
  FAILED_TO_CALL_USER_SERVICE(
      "3004", "Gọi tới User Service thất bại", HttpStatus.SERVICE_UNAVAILABLE),

  EVENT_NOT_STARTED("4000", "Sự kiện chưa bắt đầu", HttpStatus.BAD_REQUEST),
    ALREADY_CHECKED_IN("4001", "Người dùng đã điểm danh sự kiện này", HttpStatus.BAD_REQUEST);

  private final String code;
  private final String message;
  private final HttpStatus status;
}
