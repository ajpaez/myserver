package com.apr.server.dao.repository;

import com.apr.server.dao.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Long> {
}
