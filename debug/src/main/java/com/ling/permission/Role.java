package com.ling.permission;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.List;

/**
 * 自定义角色类
 *
 * 角色和权限在代码层面没有太大的区别,聚合一个 SimpleGrantedAuthority 的集合列表表示一个角色拥有的多个权限
 *
 * @author zhangling
 * @date 2023/4/24 09:17
 */
public class Role implements GrantedAuthority {

    private String name;

    // 一个角色中的多个权限，
    private List<SimpleGrantedAuthority> allowedOperations = new ArrayList<>();

    @Override
    public String getAuthority() {
        return name;
    }

    public List<SimpleGrantedAuthority> getAllowedOperations() {
        return allowedOperations;
    }

    public void setAllowedOperations(List<SimpleGrantedAuthority> allowedOperations) {
        this.allowedOperations = allowedOperations;
    }
}
