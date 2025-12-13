package com.rde.authApp.controller;

import com.rde.authApp.Services.UserService;
import com.rde.authApp.model.LoginRequest;
import com.rde.authApp.model.RegisterRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public String register(@RequestBody RegisterRequest request) {
        System.out.println("register the user");
        userService.register(request);
        return "User registered successfully!";
    }

    @PostMapping("/login")
    public String login(@RequestBody LoginRequest request) {
        System.out.println("register the user");
        String success = userService.login(request);
        return success.length()>0 ? success : "Invalid Credentials!";
    }
}
