package com.ventas.idat.users.dto;

import org.springframework.stereotype.Component;

import com.ventas.idat.users.model.User;

@Component
public class UserMapper {

    public static UserDTO toDTO(User user) {
        return UserDTO.builder()
                .id(user.getId())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .username(user.getUsername())
                .role(user.getRole())
                .build();
    }

}
