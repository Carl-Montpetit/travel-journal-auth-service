package com.traveljournal.authservice.repository;

import com.traveljournal.authservice.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    // Method to check if a user exists by username
    boolean existsByUsername(String username);

    // Other methods like findByUsername, if needed
    Optional<User> findByUsername(String username);
}
