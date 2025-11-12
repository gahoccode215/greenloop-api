package com.greenloop.reward.service.impl;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.greenloop.reward.service.CacheService;
import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CacheServiceImpl implements CacheService {

  private final RedisTemplate<String, Object> redisTemplate;
  private final ObjectMapper objectMapper;

  @Override
  public void storeWithTTL(String key, Object value, Integer timeOut, TimeUnit timeUnit) {
    this.redisTemplate.opsForValue().set(key, value, timeOut, timeUnit);
  }

  @Override
  public void store(String key, Object value) {
    this.redisTemplate.opsForValue().set(key, value);
  }

  @Override
  public Object retrieve(String key) {
    return this.redisTemplate.opsForValue().get(key);
  }

  @Override
  public Boolean hasKey(String key) {
    return this.redisTemplate.hasKey(key);
  }

  @Override
  public void remove(String key) {
    this.redisTemplate.delete(key);
  }

  @Override
  public <T> T get(String key, Class<T> clazz) {
    Object raw = redisTemplate.opsForValue().get(key);
    return raw != null ? objectMapper.convertValue(raw, clazz) : null;
  }

  @Override
  public <T> T get(String key, TypeReference<T> typeReference) {
    Object raw = redisTemplate.opsForValue().get(key);
    return raw != null ? objectMapper.convertValue(raw, typeReference) : null;
  }
}
