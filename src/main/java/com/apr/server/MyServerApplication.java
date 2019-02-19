package com.apr.server;

import com.apr.server.dao.entity.Role;
import com.apr.server.dao.entity.User;
import com.apr.server.dao.repository.RoleRepository;
import com.apr.server.dao.repository.UserRepository;
import com.apr.server.security.TypeRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Arrays;
import java.util.HashSet;

@SpringBootApplication
public class MyServerApplication {

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private RoleRepository roleRepository;

	@Autowired
	private PasswordEncoder encoder;

	public static void main(String[] args) {
		SpringApplication.run(MyServerApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(ApplicationContext ctx) {
		return args -> {

			for (TypeRole typeRole : TypeRole.values()) {
			String name = typeRole.name().split("_")[1];

				Role role = new Role();
				role.setName(name);
				roleRepository.save(role);

				User user = new User();
				user.setUserName(name.toLowerCase());
				user.setPassword(encoder.encode(name.toLowerCase()));
				user.setEnabled(true);
				user.setRoles(new HashSet<Role>(Arrays.asList(role)));

				userRepository.save(user);
			}

		};
	}


}
