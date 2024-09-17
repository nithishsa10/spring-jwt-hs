package dev.auth.security.model;

import jakarta.persistence.Entity;

@Entity
public enum Role {
    USER,
    ADMIN
}
