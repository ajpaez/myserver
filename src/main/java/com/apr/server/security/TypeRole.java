package com.apr.server.security;

import org.springframework.security.core.GrantedAuthority;

public enum TypeRole implements GrantedAuthority {
    ROLE_USER, ROLE_ADMIN;

    @Override
    public String getAuthority() {
        return name();
    }
}