package com.greenloop.notification.repository;

import com.greenloop.notification.entity.Notification;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

@Repository
public interface NotificationRepository
    extends JpaRepository<Notification, Long>, JpaSpecificationExecutor<Notification> {
  List<Notification> findByUserIdAndIsReadFalse(Long userId);
}
