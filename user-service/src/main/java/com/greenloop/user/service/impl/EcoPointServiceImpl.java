package com.greenloop.user.service.impl;

import com.greenloop.user.entity.User;
import com.greenloop.user.repository.UserRepository;
import com.greenloop.user.service.EcoPointService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class EcoPointServiceImpl implements EcoPointService {

  private final UserRepository userRepository;

  @Override
  @Transactional
  public void addEcoPoints(Long userId, Integer points) {
    log.info("Adding {} eco points to user: {}", points, userId);

    User user =
        userRepository
            .findById(userId)
            .orElseThrow(() -> new RuntimeException("User not found: " + userId));

    Integer currentPoints = user.getEcoPoints() != null ? user.getEcoPoints() : 0;
    user.setEcoPoints(currentPoints + points);

    userRepository.save(user);

    log.info(
        "Successfully added {} eco points to user: {}. New total: {}",
        points,
        userId,
        user.getEcoPoints());
  }
}
