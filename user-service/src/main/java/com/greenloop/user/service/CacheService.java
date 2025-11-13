package com.greenloop.user.service;

import java.util.concurrent.TimeUnit;

public interface CacheService {

  // ==================== Basic Operations ====================

  /**
   * Set value with expiry time
   *
   * @param key Cache key
   * @param value Value to cache
   * @param timeout Expiry duration
   * @param unit Time unit
   */
  void set(String key, Object value, long timeout, TimeUnit unit);

  /**
   * Set value without expiry (permanent until manual deletion)
   *
   * @param key Cache key
   * @param value Value to cache
   */
  void set(String key, Object value);

  /**
   * Get cached value
   *
   * @param key Cache key
   * @return Cached value or null if not exists
   */
  Object get(String key);

  /**
   * Get cached value with type casting
   *
   * @param key Cache key
   * @param type Expected class type
   * @return Typed value or null if not exists
   */
  <T> T get(String key, Class<T> type);

  /**
   * Delete cached value
   *
   * @param key Cache key
   */
  void delete(String key);
}
