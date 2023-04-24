package com.ling;

import com.ling.config.MyAuthenticationFailureHandler;
import com.ling.config.MyAuthenticationSuccessHandler;
import com.ling.config.MyLogoutSuccessHandler;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.UrlAuthorizationConfigurer;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;


@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 使用 UrlAuthorizationConfigurer 配置 FilterSecurityInterceptor
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        http.apply(new UrlAuthorizationConfigurer<>(applicationContext))
                .getRegistry()
                // 使用 RoleVoter 投票器,所以角色需要加上前缀 ROLE_
                .mvcMatchers("/admin/**").access("ROLE_admin")
                // 该方式需要地址和权限完成,不能只有一个
                .mvcMatchers("/user/**").access("ROLE_user")
                .and()
                .formLogin()
                .and()
                .csrf().disable();
    }
}
