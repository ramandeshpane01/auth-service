package com.rde.authApp.model;

import lombok.Data;

@Data
public class RefreshRequest {

    private String accessToken;
    private String refreshToken;
    private String deviceId;
}
