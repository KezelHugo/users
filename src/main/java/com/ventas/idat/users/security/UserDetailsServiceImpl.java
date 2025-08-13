package com.ventas.idat.users.security;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.ventas.idat.users.model.User;
import com.ventas.idat.users.repository.UserRepository;

@Service
public class UserDetailsServiceImpl implements UserDetailsService{

    private final UserRepository userRepository;

    public UserDetailsServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado"));
        String role = user.getRole().toUpperCase().replace("ROLE_", "");

        return org.springframework.security.core.userdetails.User.withUsername(username)
                .password(user.getPassword())
                .roles(role)
                .build();
    }
    

}
