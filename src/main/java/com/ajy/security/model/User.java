package com.ajy.security.model;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.sql.Timestamp;

@Data
@Entity
@NoArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    private String username;

    private String password;

    private String email;

    private String role;//ROLE_USER, ROLE_ADMIN

    @CreationTimestamp
    private Timestamp createDate;

    private String provider;
    private String providerId;

    @Builder
    public User(String username, String password, String email, String role, Timestamp createDate, String provider, String providerId) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.role = role;
        this.createDate = createDate;
        this.provider = provider;
        this.providerId = providerId;
    }
}
