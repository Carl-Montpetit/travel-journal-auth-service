package com.traveljournal.authservice.controller;

import com.traveljournal.authservice.model.User;
import com.traveljournal.authservice.dto.LoginUserDto;
import com.traveljournal.authservice.dto.UpdateUserDto;
import com.traveljournal.authservice.dto.UserDto;
import com.traveljournal.authservice.security.JwtUtil;
import com.traveljournal.authservice.service.AuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private AuthService authService;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // 1. Register a new user
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody User user) {
        // Log the received data for debugging
        logger.debug("Received UserDto: {}", user);

        // Check if username already exists
        if (authService.existsByUsername(user.getUsername())) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Collections.singletonMap("error", "Username already exists"));
        }

        // Encode the password
        String encodedPassword = passwordEncoder.encode(user.getPassword());
        user.setPassword(encodedPassword);

        logger.debug("User to be saved: {}", user);

        // Save the new user
        authService.saveUser(user);

        return ResponseEntity.ok(Collections.singletonMap("message", "User registered successfully"));
    }

    // 2. Login user and generate JWT token
    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody LoginUserDto loginUserDto) {
        Optional<User> authenticatedUser = authService.authenticateUser(loginUserDto.getUsername(), loginUserDto.getPassword());
        if (authenticatedUser.isPresent()) {
            String token = jwtUtil.generateJwtToken(authenticatedUser.get().getUsername());
            return ResponseEntity.ok(Collections.singletonMap("token", token));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Collections.singletonMap("error", "Invalid credentials"));
        }
    }

    // 3. Get user details by username
    @GetMapping("/user/{username}")
    public ResponseEntity<UserDto> getUserByUsername(@PathVariable String username) {
        Optional<User> user = authService.findUserByUsername(username);

        if (user.isPresent()) {
            UserDto userDto = new UserDto();
            userDto.setUsername(user.get().getUsername());
            userDto.setPassword(user.get().getPassword());
            userDto.setEmail(user.orElseThrow().getEmail());

            return ResponseEntity.ok(userDto);
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body((UserDto) Collections.singletonMap("error", "User not found"));
        }
    }

    // 4. Refresh JWT token
    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> request) {
        String token = request.get("token");
        try {
            String username = jwtUtil.extractUsername(token);
            String newToken = jwtUtil.generateJwtToken(username);
            return ResponseEntity.ok(Collections.singletonMap("token", newToken));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Collections.singletonMap("error", "Invalid token"));
        }
    }

    // 5. Reset user password
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> request) {
        String username = request.get("username");
        String newPassword = request.get("newPassword");

        Optional<User> user = authService.findUserByUsername(username);
        if (user.isPresent()) {
            User existingUser = user.get();
            existingUser.setPassword(passwordEncoder.encode(newPassword));
            authService.updateUser(existingUser);
            return ResponseEntity.ok(Collections.singletonMap("message", "Password reset successfully"));
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Collections.singletonMap("error", "User not found"));
        }
    }

    @PostMapping("/update-user")
    public ResponseEntity<String> updateUser(@RequestBody UpdateUserDto updateUserDto) {
        Optional<User> user = authService.findUserByUsername(updateUserDto.getUsername());
        if (user.isPresent()) {
            User existingUser = user.get();
            existingUser.setPassword(passwordEncoder.encode(updateUserDto.getPassword()));
            existingUser.setEmail(updateUserDto.getEmail());
            authService.updateUser(existingUser);
            return ResponseEntity.ok("User updated successfully");
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
        }
    }
}
