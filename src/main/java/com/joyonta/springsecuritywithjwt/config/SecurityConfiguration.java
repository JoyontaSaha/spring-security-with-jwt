package com.joyonta.springsecuritywithjwt.config;

import com.joyonta.springsecuritywithjwt.filter.JwtFilter;
import com.joyonta.springsecuritywithjwt.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtFilter jwtFilter;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService);
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    /**
     *  It turned out that antMatcher was working as expected
     *  & allowing all URLs as intended, but the reason for
     *  the forbidden response that was getting for the POST APIs was that
     *  Spring security was waiting for csrf token for
     *  these POST requests because CSRF protection is enabled
     *  by default in spring security.
     *
     * So in order to make it work , must provide the csrf token in POST request
     * OR temporarily turn CSRF protection off
     * (but should enable it again before going to production as this is a serious attack)
     *
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                // disabling csrf here, you should enable it before using in production
                .csrf()
                .disable()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST,"/authenticate")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
