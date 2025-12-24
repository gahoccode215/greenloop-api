package com.greenloop.order.service;

import com.greenloop.order.dto.redis.PendingOrderRedis;
import com.greenloop.order.entity.Order;
import vn.payos.model.webhooks.WebhookData;

public interface PaymentWebhookService {


    String processPayOSWebhook(WebhookData webhookData);


    Order persistOrderFromRedis(PendingOrderRedis pendingOrder, WebhookData webhookData);


    void handleSuccessfulPayment(Order order, WebhookData webhookData);


    void handleFailedPayment(Order order, WebhookData webhookData);

    void handleFailedPaymentFromRedis(PendingOrderRedis pendingOrder, WebhookData webhookData);
}
