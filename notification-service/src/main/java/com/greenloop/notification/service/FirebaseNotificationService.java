package com.greenloop.notification.service;

import com.google.firebase.messaging.*;
import com.greenloop.notification.entity.UserToken;
import com.greenloop.notification.enums.Platform;
import com.greenloop.notification.repository.UserTokenRepository;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class FirebaseNotificationService {

  private final UserTokenRepository tokenRepository;

  public void sendNotification(Long userId, String title, String body) {
    log.info("Sending notification to Firebase for userId={}", userId);
    List<UserToken> tokens = tokenRepository.findByUserId(userId);
    if (tokens.isEmpty()) return;

    List<String> tokenList = tokens.stream().map(UserToken::getToken).toList();

    MulticastMessage message =
        MulticastMessage.builder()
            .addAllTokens(tokenList)
            .setNotification(Notification.builder().setTitle(title).setBody(body).build())
            .build();

    try {
      BatchResponse response = FirebaseMessaging.getInstance().sendMulticast(message);
      System.out.println("Sent: " + response.getSuccessCount() + "/" + tokenList.size());
    } catch (FirebaseMessagingException e) {
      e.printStackTrace();
    }
  }

  public void saveUserToken(Long userId, String token, Platform platform) {
    log.info("Saving user token for userId={}, token={}", userId, token);
    if (tokenRepository.findByUserId(userId).stream().noneMatch(t -> t.getToken().equals(token))) {
      tokenRepository.save(
          UserToken.builder().userId(userId).token(token).platform(platform).build());
    }
  }
}
