package com.carportal.service;

import com.carportal.entity.User;
import com.carportal.payload.LoginDto;
import com.carportal.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {

    private UserRepository userRepository;
    private JWTService jwtService;

    public AuthService(UserRepository userRepository, JWTService jwtService) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
    }

    public String authenticate(
            LoginDto dto
    ){
        Optional<User> opUser = userRepository.findByUsername(dto.getUsername());

        if(opUser.isPresent()) {
            User user = opUser.get();
            boolean status = BCrypt.checkpw(dto.getPassword(), user.getPassword());
            if (status) {
                return jwtService.generateToken(user.getUsername());
            }
        }
            return null;
        }


}
