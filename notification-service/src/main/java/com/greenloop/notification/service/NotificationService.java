package com.greenloop.notification.service;

import com.greenloop.notification.dto.event.NotificationEvent;
import com.greenloop.notification.dto.request.TokenRequest;
import com.greenloop.notification.dto.response.NotificationResponse;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.time.LocalDateTime;

public interface NotificationService {
    void createAndSend(NotificationEvent notificationEvent);
    void registerToken(TokenRequest request);
    void unregisterToken(String token);
    Page<NotificationResponse> getNotifications(Pageable pageable);
    void markAsRead(Long notificationId);
    void markAllAsRead();
}
