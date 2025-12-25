package com.greenloop.product.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    PRODUCT_NOT_FOUND("PROD_001", "Không tìm thấy sản phẩm", HttpStatus.NOT_FOUND),
    PRODUCT_ALREADY_EXISTS("PROD_002", "Sản phẩm với định danh này đã tồn tại", HttpStatus.CONFLICT),
    INVALID_PRODUCT_DATA("PROD_003", "Dữ liệu sản phẩm không hợp lệ", HttpStatus.BAD_REQUEST),
    UPLOAD_IMAGE_ERROR("PROD_004", "Đã xảy ra lỗi khi tải lên hình ảnh", HttpStatus.INTERNAL_SERVER_ERROR),
    CATEGORY_NOT_FOUND("PROD_005", "Không tìm thấy danh mục", HttpStatus.NOT_FOUND),
    ECO_POINT_VALUE_OUT_OF_BOUNDS("PROD_006", "Giá trị eco point nằm ngoài giới hạn cho phép", HttpStatus.BAD_REQUEST),
    EVENT_OR_STAFF_NOT_VALID("PROD_007", "Sự kiện hoặc nhân viên không hợp lệ", HttpStatus.BAD_REQUEST),
    DONATION_NOT_FOUND("PROD_008", "Không tìm thấy thông tin quyên góp", HttpStatus.NOT_FOUND),
    ACCESS_DENIED("PROD_009", "Truy cập bị từ chối", HttpStatus.FORBIDDEN),
    DONATION_ITEM_STATUS_UPDATE_FAILED("PROD_010", "Cập nhật trạng thái vật phẩm quyên góp thất bại", HttpStatus.INTERNAL_SERVER_ERROR),
    DONATION_ITEM_NOT_FOUND("PROD_011", "Không tìm thấy vật phẩm quyên góp", HttpStatus.NOT_FOUND),
    PRODUCT_ASSET_NOT_FOUND("PROD_012", "Không tìm thấy tài nguyên của sản phẩm", HttpStatus.NOT_FOUND),
    EVENT_NOT_FOUND("PROD_013", "Không tìm thấy sự kiện", HttpStatus.NOT_FOUND),
    EVENT_PRODUCT_TIME_CONFLICT("PROD_014", "Thời gian trưng bày sản phẩm trong sự kiện bị xung đột", HttpStatus.CONFLICT),
    EVENT_PRODUCT_MAPPING_NOT_FOUND("PROD_015", "Không tìm thấy dữ liệu ánh xạ sản phẩm - sự kiện", HttpStatus.NOT_FOUND),
    EVENT_PRODUCT_ALREADY_EXISTS("PROD_016", "Ánh xạ sản phẩm - sự kiện đã tồn tại", HttpStatus.CONFLICT),
    ECO_POINT_RULE_NOT_FOUND("PROD_017", "Không tìm thấy quy tắc eco point", HttpStatus.NOT_FOUND),
    EVENT_SERVICE_ERROR("PROD_018", "Lỗi khi giao tiếp với dịch vụ sự kiện", HttpStatus.SERVICE_UNAVAILABLE),


    PRODUCT_ALREADY_SOLD("PROD_017", "Product already sold", HttpStatus.CONFLICT),
    PRODUCT_NOT_AVAILABLE("PROD_018", "Product not available", HttpStatus.BAD_REQUEST),
    PRODUCT_NOT_IN_EVENT("PROD_019", "Product not assigned to this event", HttpStatus.BAD_REQUEST),
    PRODUCT_NOT_YET_DISPLAYABLE("PROD_020", "Product display time not yet started", HttpStatus.BAD_REQUEST),
    PRODUCT_DISPLAY_EXPIRED("PROD_021", "Product display time expired", HttpStatus.BAD_REQUEST),
    PRODUCT_NOT_DISPLAYED("PROD_022", "Product not in displayed status", HttpStatus.BAD_REQUEST),


    ECO_POINT_UPDATE_FAILED("PROD_023", "Lỗi trong quá trình cộng điểm", HttpStatus.INTERNAL_SERVER_ERROR),
    DONATION_ITEM_ALREADY_CONVERTED("PROD_024", "Vật phẩm quyên góp đã được chuyển đổi thành sản phẩm", HttpStatus.BAD_REQUEST),
    ECO_POINT_RULE_INACTIVE("PROD_025", "Quy tắc eco point không hoạt động. Vui lòng chọn eco point bạn cảm thấy phù hợp hoặc liên hệ Admin.", HttpStatus.BAD_REQUEST),
    INVALID_EVENT_PRODUCT_STATUS_TRANSITION("PROD_026", "Chuyển đổi trạng thái sản phẩm sự kiện không hợp lệ", HttpStatus.BAD_REQUEST);

    private final String code;
    private final String message;
    private final HttpStatus status;
}
