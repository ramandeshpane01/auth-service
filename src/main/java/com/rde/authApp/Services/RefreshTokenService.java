package com.rde.authApp.Services;

import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.UUID;

@Service
public class RefreshTokenService {


    private static final long REFRESH_TOKEN_TTL_DAYS = 30;

    private final StringRedisTemplate redisTemplate;

    public RefreshTokenService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }


    public String generateRefreshToken(Long userId, String deviceId) {

        String rawToken = UUID.randomUUID().toString();
        String hashedToken = hash(rawToken);

        String key = "refresh:" + hashedToken;
        String value = userId + ":" + deviceId;

        redisTemplate.opsForValue().set(
                key,
                value,
                Duration.ofDays(REFRESH_TOKEN_TTL_DAYS)
        );

        return rawToken;
    }



    public boolean validateRefreshToken(
            Long userId,
            String deviceId,
            String refreshToken
    ) {
        String hashedToken = hash(refreshToken);
        String key = "refresh:" + hashedToken;

        String value = redisTemplate.opsForValue().get(key);
        if (value == null) return false;

        String[] parts = value.split(":");
        Long storedUserId = Long.parseLong(parts[0]);
        String storedDeviceId = parts[1];

        return storedUserId.equals(userId)
                && storedDeviceId.equals(deviceId);
    }


    public void revokeRefreshToken(String refreshToken) {
        String key = "refresh:" + hash(refreshToken);
        redisTemplate.delete(key);
    }


    private String buildKey(Long userId, String deviceId) {
        return "refresh:" + userId + ":" + deviceId;
    }

    
    private String hash(String token) {
        return DigestUtils.sha256Hex(token);
    }
}
