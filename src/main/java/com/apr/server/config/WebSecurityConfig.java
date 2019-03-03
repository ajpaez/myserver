package com.apr.server.config;

import com.apr.server.security.AuthenticationSuccessHandlerImpl;
import com.apr.server.security.Constants;
import com.apr.server.security.LoggingAccessDeniedHandler;
import com.apr.server.security.ldap.CustomLdapUserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.context.WebApplicationContext;

import javax.annotation.PostConstruct;
import javax.sql.DataSource;
import java.util.Collection;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, proxyTargetClass = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Value("${authentication.method}")
    private String authenticationMethod;

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
        switch (authenticationMethod) {
            case Constants
                    .AUTHENTICATION_METHOD_DB:
                auth.userDetailsService(userDetailsService)
                        .passwordEncoder(passwordEncoder())
                        .and()
                        .authenticationProvider(authenticationProvider())
                        .jdbcAuthentication()
                        .dataSource(dataSource);
                break;
            case Constants
                    .AUTHENTICATION_METHOD_LDAP:
                auth
                        .ldapAuthentication()
                        .userDnPatterns("uid={0},ou=people")
                        .groupSearchBase("ou=groups")
                        .contextSource()
                        .url("ldap://localhost:8389/dc=springframework,dc=org")
                        .and()
                        .userDetailsContextMapper(userDetailsContextMapper())
                        .passwordCompare()
                        .passwordEncoder(passwordEncoder())//remove for user with plain text pass
                        .passwordAttribute("userPassword");
                break;
            case Constants
                    .AUTHENTICATION_METHOD_MEMORY:
                auth
                        .inMemoryAuthentication()
                        .withUser("user").password("password").roles("USER")
                        .and()
                        .withUser("admin").password("admin").roles("ADMIN");
                break;
            default:
                break;
        }

    }

    @Bean
    public UserDetailsContextMapper userDetailsContextMapper() {
        return new LdapUserDetailsMapper() {
            @Override
            public UserDetails mapUserFromContext(DirContextOperations ctx, String username, Collection<? extends GrantedAuthority> authorities) {
                UserDetails details = super.mapUserFromContext(ctx, username, authorities);
                return new CustomLdapUserDetails((LdapUserDetails) details);
            }
        };
    }


    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        final DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        final BCryptPasswordEncoder crypt = new BCryptPasswordEncoder();
        return new PasswordEncoder() {
            @Override
            public String encode(CharSequence rawPassword) {
                // Prefix so that apache directory understands that bcrypt has been used.
                // Without this, it assumes SSHA and fails during authentication.
                return "{CRYPT}" + crypt.encode(rawPassword);
            }

            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                return crypt.matches(rawPassword, encodedPassword.substring(7));
            }
        };
    }


}
