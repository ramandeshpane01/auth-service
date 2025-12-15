package com.rde.authApp.model;

import lombok.Data;

@Data
public class LogoutRequest {

    private String refreshToken;
}
