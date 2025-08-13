package com.ventas.idat.users.dto;

import com.ventas.idat.users.model.User;

public class UserMapper {

    private UserMapper() {
        throw new UnsupportedOperationException("Esta clase no puede ser instanciada");
    }


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
