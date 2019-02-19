package com.apr.server.config;

import com.apr.server.security.AuthenticationSuccessHandlerImpl;
import com.apr.server.security.LoggingAccessDeniedHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.context.WebApplicationContext;

import javax.annotation.PostConstruct;
import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, proxyTargetClass = true)

public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private WebApplicationContext applicationContext;
    private UserDetailsService userDetailsService;
    @Autowired
    private AuthenticationSuccessHandlerImpl successHandler;
    @Autowired
    private DataSource dataSource;
    @Autowired
    private LoggingAccessDeniedHandler accessDeniedHandler;

    @PostConstruct
    public void completeSetup() {
        userDetailsService = applicationContext.getBean(UserDetailsService.class);
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.
                csrf().disable();

        http.headers().frameOptions().disable();

        http
                .authorizeRequests()
                    .antMatchers(
                            "/js/**",
                            "/css/**",
                            "/img/**",
                            "/h2/**",
                            "/webjars/**").permitAll()
                    .antMatchers("/", "/index", "/access-denied").permitAll()
                    .anyRequest().authenticated()
                .and()
                    .formLogin()
                        .loginPage("/login")
                        .successForwardUrl("/hello")
                        .defaultSuccessUrl("/hello")
                        .failureUrl("/login?error=true")
                        .permitAll()
                        .usernameParameter("username") // make sure your form has correct params
                        .passwordParameter("password")
                        .successHandler(successHandler)
                .and()
                    .logout()
                        .invalidateHttpSession(true)
                        .clearAuthentication(true)
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                .and()
                    .rememberMe()
                    .tokenValiditySeconds(60 * 60)
                .and()
                    .exceptionHandling()
                        .accessDeniedPage("/access_denied")
                        .accessDeniedHandler(accessDeniedHandler);

    }




    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService)
                .passwordEncoder(passwordEncoder())
                .and()
                .authenticationProvider(authenticationProvider())
                .jdbcAuthentication()
                .dataSource(dataSource);
    }


    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        final DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

/*
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth)
            throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser("user").password(passwordEncoder().encode("user")).roles("USER")
                .and()
                .withUser("admin").password(passwordEncoder().encode("admin")).roles("ADMIN");
    }

         auth
             .jdbcAuthentication()
                 .dataSource(dataSource)
                 .usersByUsernameQuery(
                         "SELECT name as username, password, enable FROM users where name=?")
                 .authoritiesByUsernameQuery(
                         "SELECT users.name as username, roles.name as role FROM users INNER JOIN user_role ON users.id = user_role.user_id INNER JOIN roles ON user_role.role_id = roles.id WHERE users.name = ?")
                 .passwordEncoder(passwordEncoder());
     }


    */

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }



}
