package shop.mtcoding.security_app.service;

import java.util.Optional;

import javax.transaction.Transactional;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import shop.mtcoding.security_app.core.jwt.MyJwtProvider;
import shop.mtcoding.security_app.dto.UserRequest;
import shop.mtcoding.security_app.dto.UserResponse;
import shop.mtcoding.security_app.model.User;
import shop.mtcoding.security_app.model.UserRepository;

@RequiredArgsConstructor
@Service
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    /*
     * 1. 트랜잭션 관리
     * 2. 영속성 객체 변경 감지
     * 3. RequestDTO 받기
     * 4. 비지니스 로직 처리하기
     * 5. ResponseDTO 응답하기
     */

    @Transactional
    public UserResponse.JoinDTO 회원가입(UserRequest.JoinDTO joinDTO) {
        String rawPassword = joinDTO.getPassword();
        String encPassword = passwordEncoder.encode(rawPassword);
        joinDTO.setPassword(encPassword);
        User userPS = userRepository.save(joinDTO.toEntity());
        return new UserResponse.JoinDTO(userPS);
    }

    public String 로그인(UserRequest.LoginDTO loginDTO) {
        Optional<User> userOP = userRepository.findByUsername(loginDTO.getUsername());
        if (userOP.isPresent()) {
            User userPS = userOP.get();
            if (passwordEncoder.matches(loginDTO.getPassword(), userPS.getPassword())) {
                String jwt = MyJwtProvider.create(userPS);
                return jwt;
            }
            throw new RuntimeException("password 불일치");
        } else {
            throw new RuntimeException("username 불일치");
        }
    }

}
