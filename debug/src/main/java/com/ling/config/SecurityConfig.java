package com.ling.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 配置用户权限关联关系
     * @param auth the {@link AuthenticationManagerBuilder} to use
     * @throws Exception
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //
        auth.inMemoryAuthentication()
                .withUser("ling").password("{noop}123").roles("admin")
                .and()
                .withUser("zhang").password("{noop}123").roles("user")
                .and()
                .withUser("bai").password("{noop}123").authorities("READ_INFO");

    }

    // 角色继承
    @Bean
    RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        // admin 继承 user(admin 可以访问 /permission/user/hello)
        roleHierarchy.setHierarchy("ROLE_admin > ROLE_user");
        return roleHierarchy;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()    // 开启权限配置
                .antMatchers("/permission/admin/**").hasRole("admin")
                // 权限表达试
                .antMatchers("/permission/user/**").access("hasAnyRole('user')")
                // 用户必须具备 READ_INFO 权限才可以访问 /getinfo
                .antMatchers("/permission/getinfo").hasAuthority("READ_INFO")
                // 剩余请求只要认证后的用户就可以访问,可以通过 access 方法设置权限表达式
                .anyRequest().access("isAuthenticated()")
                // 所有请求都需要认证后才可访问
                // .anyRequest().authenticated()
                .and()
                // 表单登录配置
                .formLogin()
                .loginPage("/login.html")
                .loginProcessingUrl("/doLogin")
//                .defaultSuccessUrl("/index")
                .successHandler(new MyAuthenticationSuccessHandler())
//               重定向客户端跳转，不方便携带请求失败的异常信息（只能放在 URL 中）
               .failureUrl("/mylogin.html")
//                .failureForwardUrl("/mylogin.html")
                .failureHandler(new MyAuthenticationFailureHandler())
                .usernameParameter("uname")
                .passwordParameter("passwd")
                .permitAll()
                .and()
                // 开启注销登录配置
                .logout()
                .logoutSuccessHandler(new MyLogoutSuccessHandler())
//                .logoutSuccessUrl("/mylogin.url")
                // 定义多个注销请求路径
//                .logoutRequestMatcher(
//                        new OrRequestMatcher(
//                                new AntPathRequestMatcher("/logout1","GET"),
//                                new AntPathRequestMatcher("logout2","POST")
//                        )
//                )
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .logoutSuccessUrl("/mylogin.html")
                .and()
                // 禁用 csrf 防御
                .csrf().disable();
    }

    // 登录成功跳转配置
    SavedRequestAwareAuthenticationSuccessHandler successHandler(){
        SavedRequestAwareAuthenticationSuccessHandler handler = new SavedRequestAwareAuthenticationSuccessHandler();
        handler.setDefaultTargetUrl("/index");
        handler.setTargetUrlParameter("target");
        return handler;
    }

    // 登录失败处理配置
    SimpleUrlAuthenticationFailureHandler failureHandler(){
        SimpleUrlAuthenticationFailureHandler handler = new SimpleUrlAuthenticationFailureHandler("/mylogin.html");
        // 登录失败后通过服务端跳转回登录页面
        handler.setUseForward(true);
        return handler;
    }

    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
}
