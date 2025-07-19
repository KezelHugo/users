package com.ventas.idat.users.service;

import java.util.List;
import java.util.Optional;

import com.ventas.idat.users.dto.ApiResponse;
import com.ventas.idat.users.dto.LoginRequest;
import com.ventas.idat.users.dto.UserDTO;
import com.ventas.idat.users.model.User;

public interface UserService {

    public ApiResponse<String> login(LoginRequest request);

    public ApiResponse<UserDTO> getUserDetail(String username);

    public Optional<User> findByUsername(String username);

    public User register(User user);

    public ApiResponse<List<UserDTO>> getAll();
    
}
