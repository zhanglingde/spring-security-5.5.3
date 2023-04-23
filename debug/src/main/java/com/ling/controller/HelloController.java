package com.ling.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class HelloController {

    // 需要登录才可访问
    @GetMapping("/hello")
    public String hello(){
        return "hello spring security";
    }

    // 取登录用户信息
    @GetMapping("/authentication")
    public void authentication(Authentication authentication){
        System.out.println(authentication);
    }

    // 取登录用户信息
    @GetMapping("/principal")
    public void principal(Principal principal){
        System.out.println(principal);
    }
}