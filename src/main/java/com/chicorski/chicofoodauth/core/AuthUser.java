package com.chicorski.chicofoodauth.core;

import com.chicorski.chicofoodauth.domain.Usuario;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;
import java.util.Collections;

@Getter
public class AuthUser extends User {

    private static final long serialVersionUID = 1l;

    private Long userId;
    private String fullName;

    public AuthUser(Usuario usuario, Collection<? extends GrantedAuthority> grantedAuthorities) {
        super(usuario.getEmail(), usuario.getSenha(), grantedAuthorities);

        this.userId = usuario.getId();
        this.fullName = usuario.getNome();
    }
}
