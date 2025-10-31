package com.greenloop.user.constant;

public final class JwtConstants {

  // Token types
  public static final String TOKEN_TYPE_ACCESS = "ACCESS";
  public static final String TOKEN_TYPE_REFRESH = "REFRESH";

  // JWT Claims
  public static final String CLAIM_USER_ID = "userId";
  public static final String CLAIM_EMAIL = "email";
  public static final String CLAIM_ROLE = "roles";
  public static final String CLAIM_JTI = "jti";
  public static final String CLAIM_TYPE = "type";

  // Redis keys
  public static final String REDIS_BLACKLIST_PREFIX = "bl:";
}
