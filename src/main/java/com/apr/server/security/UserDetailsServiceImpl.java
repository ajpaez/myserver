package com.apr.server.security;

import com.apr.server.dao.entity.User;
import com.apr.server.dao.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import javax.annotation.PostConstruct;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private WebApplicationContext applicationContext;
    private UserRepository userRepository;

    public UserDetailsServiceImpl() {
        super();
    }

    @PostConstruct
    public void completeSetup() {
        userRepository = applicationContext.getBean(UserRepository.class);
    }


    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUserName(username);

        if (user == null) {
            throw new UsernameNotFoundException(username);
        }

        return new UserDetailsImpl(user);
    }
}
