package com.PianzinAV.animalInsta.service;

import com.PianzinAV.animalInsta.constant.ERole;
import com.PianzinAV.animalInsta.dto.UserDTO;
import com.PianzinAV.animalInsta.entity.User;
import com.PianzinAV.animalInsta.exception.UserExistException;
import com.PianzinAV.animalInsta.payload.request.SignupRequest;
import com.PianzinAV.animalInsta.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Principal;

@Service
public class UserService {
    public static final Logger LOG = LoggerFactory.getLogger(UserService.class);

    @Autowired
    public UserService(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public User createUser(SignupRequest userIn) {
        User user = new User();
        user.setEmail(userIn.getEmail());
        user.setName(userIn.getFirstname());
        user.setLastname(userIn.getLastname());
        user.setUsername(userIn.getUsername());
        user.setPassword(passwordEncoder.encode(userIn.getPassword()));
        user.getRoles().add(ERole.ROLE_USER);

        try {
            LOG.info("Saving User {} ", userIn.getEmail());

            return userRepository.save(user);
        } catch (Exception e) {
            LOG.error("Error during registration");
            throw new UserExistException("The user " + user.getUsername() + " already exist. Please check credentials");
        }
    }
        //
    public User updateUser(UserDTO userDTO, Principal principal) {
User user=getUserByPrincipal(principal);
        user.setName(userDTO.getFirstname());
        user.setLastname(userDTO.getLastname());
        user.setBio(userDTO.getBio());

        return userRepository.save(user);
    }
    public User getCurrentUser(Principal principal) {
        return getUserByPrincipal(principal);
    }
    private User getUserByPrincipal(Principal principal){
        String username= principal.getName();
        return userRepository.findUserByUsername(username)
                .orElseThrow(()->new UsernameNotFoundException("Username not found with username "+username));
    }
}
