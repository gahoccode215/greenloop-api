package com.greenloop.notification.service.impl;

import com.greenloop.notification.dto.event.NotificationEvent;
import com.greenloop.notification.dto.request.TokenRequest;
import com.greenloop.notification.dto.response.NotificationResponse;
import com.greenloop.notification.entity.Notification;
import com.greenloop.notification.entity.UserToken;
import com.greenloop.notification.repository.NotificationRepository;
import com.greenloop.notification.repository.UserTokenRepository;
import com.greenloop.notification.service.FirebaseNotificationService;
import com.greenloop.notification.service.NotificationService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class NotificationServiceImpl implements NotificationService {
    private final NotificationRepository notificationRepository;
    private final UserTokenRepository userTokenRepository;
    private final FirebaseNotificationService firebase;

    @Override
    public void createAndSend(NotificationEvent notificationEvent) {
        log.info("Notification event received: {}", notificationEvent);
        Notification n = notificationRepository.save(Notification.builder()
                .userId(notificationEvent.getUserId())
                .title(notificationEvent.getTitle())
                .body(notificationEvent.getMessage())
                .isRead(false)
                .build());

        firebase.sendNotification(notificationEvent.getUserId(), notificationEvent.getTitle(), notificationEvent.getMessage());
        log.info("Notification event sent to firebase: {}", notificationEvent);
        notificationRepository.save(n);
    }

    @Override
    public void registerToken(TokenRequest request) {
        log.info("Register token request: {}", request);

        Optional<UserToken> existingToken = userTokenRepository.findByToken(request.getToken());

        if (existingToken.isPresent()) {
            log.info("Token {} đã tồn tại cho userId {}", request.getToken(), existingToken.get().getUserId());
            UserToken token = existingToken.get();
            token.setUserId(request.getUserId());
            token.setPlatform(request.getPlatform());
            userTokenRepository.save(token);
        } else {
            UserToken newToken = UserToken.builder()
                    .userId(request.getUserId())
                    .token(request.getToken())
                    .platform(request.getPlatform())
                    .createdAt(LocalDateTime.now())
                    .build();
            userTokenRepository.save(newToken);
            log.info("Token {} đã được đăng ký cho userId {}", request.getToken(), request.getUserId());
        }
    }

    @Override
    @Transactional
    public void unregisterToken(String token) {
        log.info("Unregister token: {}", token);
        userTokenRepository.deleteByToken(token);
        log.info("Token {} đã được hủy đăng ký", token);
    }

    @Override
    public Page<NotificationResponse> getNotifications(Pageable pageable) {
        Long userId = getCurrentUserId();
        Specification<Notification> spec = (root, query, criteriaBuilder) ->
                criteriaBuilder.equal(root.get("userId"), userId);

        Page<Notification> notifications = notificationRepository.findAll(spec, pageable);

        return notifications.map(notification -> NotificationResponse.builder()
                .id(notification.getId())
                .title(notification.getTitle())
                .message(notification.getBody())
                .isRead(notification.isRead())
                .createdAt(notification.getCreatedAt())
                .build());
    }

    @Override
    public void markAsRead(Long notificationId) {
        Notification notification = notificationRepository.findById(notificationId).orElse(null);
        if (notification != null) {
            notification.setRead(true);
            notificationRepository.save(notification);
            log.info("Notification {} marked as read", notificationId);
        } else {
            log.warn("Notification {} not found", notificationId);
        }
    }

    @Override
    public void markAllAsRead() {
        Long userId = getCurrentUserId();
        List<Notification> notifications = notificationRepository.findByUserIdAndIsReadFalse(userId);
        for (Notification notification : notifications) {
            notification.setRead(true);
        }
        notificationRepository.saveAll(notifications);
        log.info("All notifications for user {} marked as read", userId);
    }

    private Long getCurrentUserId() {
        return Long.valueOf(
                SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString());
    }

}
