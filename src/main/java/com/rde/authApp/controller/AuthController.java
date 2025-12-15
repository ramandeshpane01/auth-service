package com.rde.authApp.controller;

import com.rde.authApp.Services.RefreshTokenService;
import com.rde.authApp.Services.UserService;
import com.rde.authApp.exception.UserAlreadyExistsException;
import com.rde.authApp.model.*;
import com.rde.authApp.security.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private RefreshTokenService refreshTokenService;
    @PostMapping("/register")
    public ResponseEntity<String> register(
            @RequestBody RegisterRequest request) {

        try {
            userService.register(request);
            return ResponseEntity
                    .status(HttpStatus.CREATED)
                    .body("User registered successfully");

        } catch (UserAlreadyExistsException e) {
            return ResponseEntity
                    .status(HttpStatus.CONFLICT)
                    .body("User already exists");

        } catch (IllegalArgumentException e) {
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(e.getMessage());

        } catch (Exception e) {
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Registration failed");
        }
    }


    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        try {
            User user=userService.authenticate(request);

            String accessToken =
                    jwtUtil.generateToken(
                            user.getId()
                    );

            String refreshToken =
                    refreshTokenService.generateRefreshToken(
                            user.getId(),
                            request.getDeviceId()
                    );

            return ResponseEntity.ok(
                    new LoginResponse(accessToken, refreshToken)
            );

        } catch (BadCredentialsException e) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .build();

        } catch (Exception e) {

            System.out.println(e);
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .build();
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshRequest request) {


        Long userId = jwtUtil.extractUserIdFromExpiredToken(request.getAccessToken());
        System.out.println(userId);

        boolean valid = refreshTokenService.validateRefreshToken(
                userId,
                request.getDeviceId(),
                request.getRefreshToken()
        );

        if (!valid) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid refresh token");
        }

        // ROTATION
        refreshTokenService.revokeRefreshToken(request.getRefreshToken());

        String newRefreshToken =
                refreshTokenService.generateRefreshToken(userId, request.getDeviceId());

        String newAccessToken =
                jwtUtil.generateToken(userId);

        return ResponseEntity.ok(
                Map.of(
                        "accessToken", newAccessToken,
                        "refreshToken", newRefreshToken
                )
        );
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody LogoutRequest request) {

        refreshTokenService.revokeRefreshToken(
                request.getRefreshToken()
        );

        return ResponseEntity.ok("Logged out successfully");
    }

}
