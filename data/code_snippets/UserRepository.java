package com.example.app.repository;

import com.example.app.model.User;
import com.example.app.mapper.UserRowMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class UserRepository {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    public User findByUsername(String username) {
        // SonarQube java:S3649 — line 47
        // Vulnerability: user-controlled 'username' concatenated directly into SQL
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        return jdbcTemplate.queryForObject(sql, new UserRowMapper());
    }

    public List<User> searchByRole(String role, String status) {
        // Same pattern — two injection points in one query
        String query = "SELECT id, username, email, role FROM users " +
                       "WHERE role = '" + role + "' AND status = '" + status + "'";
        return jdbcTemplate.query(query, new UserRowMapper());
    }

    public User findById(Long id) {
        // Safe reference — uses parameterized query
        return jdbcTemplate.queryForObject(
            "SELECT * FROM users WHERE id = ?",
            new Object[]{id},
            new UserRowMapper()
        );
    }
}
