package com.ventas.idat.users.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.hamcrest.Matchers.nullValue;

import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.ventas.idat.users.config.JWTUtil;
import com.ventas.idat.users.dto.ApiResponse;
import com.ventas.idat.users.dto.LoginRequest;
import com.ventas.idat.users.dto.UserDTO;
import com.ventas.idat.users.model.User;
import com.ventas.idat.users.security.UserDetailsServiceImpl;
import com.ventas.idat.users.service.UserServiceImpl;

@SpringBootTest
@AutoConfigureMockMvc
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private UserServiceImpl userService;

    @MockitoBean
    private JWTUtil jwtUtil;

    @MockitoBean
    private UserDetailsServiceImpl userDetailsService;

    @Test
    void testRegister() throws Exception {
        User user = new User();
        user.setFirstName("Test");
        user.setLastName("Test");
        user.setUsername("test@idat.pe");
        user.setPassword("1234");
        user.setRole("admin");

        when(userService.register(any(User.class))).thenReturn(user);
        
        mockMvc.perform(post("/api/users/register")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(user)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("test@idat.pe"));
    }

    @Test
    void testLogin() throws Exception {
        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUsername("richard");
        loginRequest.setPassword("1234");

        ApiResponse<String> response = new ApiResponse<>();
        response.setResponseCode(200);
        response.setResponseMessage("ok");
        response.setData("token");
        when(userService.login(any(LoginRequest.class))).thenReturn(response);

        mockMvc.perform(post("/api/users/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data").value("token"));
    }

    @Test
    @WithMockUser(username = "admin", roles = {"ADMIN"})
    void testGetAllUsers() throws Exception {
        UserDTO userDTO = UserDTO.builder()
                                    .firstName("test")
                                    .lastName("test")
                                    .username("test")
                                    .role("admin")
                                    .build();

        ApiResponse<List<UserDTO>> response = new ApiResponse<>();
        response.setResponseCode(200);
        response.setResponseMessage("ok");
        response.setData(List.of(userDTO));

        when(userService.getAll()).thenReturn(response);
        mockMvc.perform(get("/api/users/"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data[0].username").value("test"));
    }

    @Test
    @WithMockUser(username = "test@idat.pe", roles = {"ADMIN"})
    void testGetProfileSuccess() throws Exception {
        UserDTO userDTO = UserDTO.builder()
                .firstName("Test")
                .lastName("User")
                .username("test@idat.pe")
                .role("admin")
                .build();

        ApiResponse<UserDTO> response = new ApiResponse<>();
        response.setResponseCode(HttpStatus.OK.value());
        response.setResponseMessage("Usuario encontrado");
        response.setData(userDTO);

        when(userService.getUserDetail("test@idat.pe")).thenReturn(response);

        mockMvc.perform(get("/api/users/profile"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.responseMessage").value("Usuario encontrado"))
                .andExpect(jsonPath("$.data.username").value("test@idat.pe"))
                .andExpect(jsonPath("$.data.role").value("admin"));
    }

    @Test
    @WithMockUser(username = "ghost@idat.pe", roles = {"ADMIN"})
    void testGetProfileNotFound() throws Exception {
        ApiResponse<UserDTO> response = new ApiResponse<>();
        response.setResponseCode(HttpStatus.NOT_FOUND.value());
        response.setResponseMessage("Usuario no encontrado");
        response.setData(null);

        when(userService.getUserDetail("ghost@idat.pe")).thenReturn(response);

        mockMvc.perform(get("/api/users/profile"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.responseMessage").value("Usuario no encontrado"))
                .andExpect(jsonPath("$.data", nullValue()));
    }

}
