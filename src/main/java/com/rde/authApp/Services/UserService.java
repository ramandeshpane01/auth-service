package com.rde.authApp.Services;

import com.rde.authApp.model.LoginRequest;
import com.rde.authApp.model.RegisterRequest;
import com.rde.authApp.model.User;
import com.rde.authApp.repo.UserRepository;
import com.rde.authApp.security.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    @Autowired
    private UserRepository repo;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private PasswordEncoder encoder;

    public void register(RegisterRequest req) {

        User user = new User();
        user.setEmail(req.getEmail());
        user.setPasswordHash(encoder.encode(req.getPassword()));  // encrypt password

        repo.save(user);
    }

    public String login(LoginRequest req) {

        User user = repo.findByEmail(req.getEmail())
                .orElseThrow(() -> new RuntimeException("Invalid credentials"));

        if (!encoder.matches(req.getPassword(), user.getPasswordHash())) {
            throw new RuntimeException("Invalid credentials");
        }

        return jwtUtil.generateToken(user.getEmail());
    }
}

