package com.greenloop.product.service;

import com.fasterxml.jackson.core.type.TypeReference;

import java.util.concurrent.TimeUnit;

public interface CacheService {
    void storeWithTTL(String key, Object value, Integer timeOut, TimeUnit timeUnit);

    void store(String key, Object value);

    Object retrieve(String key);

    Boolean hasKey(String key);

    void remove(String key);

    <T> T get(String key, Class<T> clazz);

    <T> T get(String key, TypeReference<T> typeReference);
}
