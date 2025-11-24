package com.greenloop.order.constant;


public final class OrderHistoryConstants {

    private OrderHistoryConstants() {
    }

    public static final class EventType {
        public static final String ORDER_CREATED = "ORDER_CREATED";
        public static final String SHIPPING_STATUS_CHANGED = "SHIPPING_STATUS_CHANGED";
        public static final String ORDER_STATUS_CHANGED = "ORDER_STATUS_CHANGED";

        private EventType() {}
    }


    public static final class ChangedByRole {
        public static final String CUSTOMER = "CUSTOMER";
        public static final String STAFF = "STAFF";
        public static final String SYSTEM = "SYSTEM";

        private ChangedByRole() {}
    }
}
