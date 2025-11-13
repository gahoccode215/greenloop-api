package com.greenloop.user.service.impl;

import com.greenloop.user.service.CacheService;
import java.util.concurrent.TimeUnit;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class CacheServiceImpl implements CacheService {

  private final RedisTemplate<String, Object> redisTemplate;

  public CacheServiceImpl(
      @Qualifier("redisObjectTemplate") RedisTemplate<String, Object> redisTemplate) {
    this.redisTemplate = redisTemplate;
  }

  @Override
  public void set(String key, Object value, long timeout, TimeUnit unit) {
    redisTemplate.opsForValue().set(key, value, timeout, unit);
  }

  @Override
  public void set(String key, Object value) {
    redisTemplate.opsForValue().set(key, value);
  }

  @Override
  public Object get(String key) {
    return redisTemplate.opsForValue().get(key);
  }

  @Override
  public <T> T get(String key, Class<T> type) {
    Object value = redisTemplate.opsForValue().get(key);
    return value != null ? (T) value : null;
  }

  @Override
  public void delete(String key) {
    redisTemplate.delete(key);
  }
}
