package com.traveljournal.authservice.controller;

import com.traveljournal.authservice.model.User;
import com.traveljournal.authservice.security.JwtUtil;
import com.traveljournal.authservice.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody User user) {
        try {
            authService.registerUser(user.getUsername(), user.getPassword());
            return ResponseEntity.ok("User registered successfully");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody User user) {
        return authService.authenticateUser(user.getUsername(), user.getPassword())
                .map(authenticatedUser -> {
                    String token = jwtUtil.generateJwtToken(authenticatedUser.getUsername());
                    return ResponseEntity.ok(token);
                })
                .orElse(ResponseEntity.status(401).body("Invalid credentials"));
    }
}