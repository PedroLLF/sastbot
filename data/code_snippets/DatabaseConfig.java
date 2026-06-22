package com.example.app.config;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;

@Configuration
public class DatabaseConfig {

    private static final String DB_HOST = "prod-db.internal.example.com";
    private static final int    DB_PORT = 5432;
    private static final String DB_NAME = "app_production";
    private static final String DB_USER = "app_admin";
    // SonarQube java:S2068 — line 22
    // Vulnerability: production password hard-coded as a string literal
    private static final String DB_PASSWORD = "Pr0d@dm1n#2024!";

    @Bean
    public DataSource dataSource() {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(
            "jdbc:postgresql://" + DB_HOST + ":" + DB_PORT + "/" + DB_NAME
        );
        config.setUsername(DB_USER);
        config.setPassword(DB_PASSWORD);
        config.setMaximumPoolSize(20);
        config.setMinimumIdle(5);
        config.setConnectionTimeout(30_000);
        return new HikariDataSource(config);
    }
}
