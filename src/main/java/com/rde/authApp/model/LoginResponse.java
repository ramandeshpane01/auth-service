package com.rde.authApp.model;

import lombok.Data;

@Data
public class LoginResponse {

    private String refreshToken;
    private String accessToken;

    public LoginResponse(String accessToken, String refreshToken) {
        this.accessToken=accessToken;
        this.refreshToken=refreshToken;
    }
}
