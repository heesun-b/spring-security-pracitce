package shop.mtcoding.security_app.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import shop.mtcoding.security_app.core.auth.MyUserDetails;
import shop.mtcoding.security_app.core.jwt.MyJwtProvider;
import shop.mtcoding.security_app.dto.ResponseDTO;
import shop.mtcoding.security_app.dto.UserRequest;
import shop.mtcoding.security_app.dto.UserResponse;
import shop.mtcoding.security_app.model.UserRepository;
import shop.mtcoding.security_app.service.UserService;

/*
 * 로그 레벨 : trace, debug, info, warn, error
 * 로그 남기는 방법 - 1) 파일로 남기기 2) 로그 전용 db 사용
 */

@RequiredArgsConstructor
@Controller
public class HelloController {
    private final UserService userService;
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;

    @Value("${meta.name}")
    private String name;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody UserRequest.LoginDTO loginDTO) {
        String jwt = userService.로그인(loginDTO);
        return ResponseEntity.ok().header(MyJwtProvider.HEADER, jwt).body("로그인 ok");
    }

    @GetMapping("/users/{id}")
    public ResponseEntity<?> userCheck(@PathVariable Long id,
            @AuthenticationPrincipal MyUserDetails myUserDetails) {

        Long userId = myUserDetails.getUser().getId();
        String role = myUserDetails.getUser().getRole();
        return ResponseEntity.ok().body(userId + " : " + role);
    }

    @GetMapping("/")
    public ResponseEntity<?> hello() {
        return ResponseEntity.ok().body(name);
    }

    @GetMapping("/loginForm")
    public String loginForm() {
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @PostMapping("/join")
    public ResponseEntity<?> join(UserRequest.JoinDTO joinDTO) {
        UserResponse.JoinDTO data = userService.회원가입(joinDTO);
        ResponseDTO<?> responseDTO = new ResponseDTO<>().data(data);
        return ResponseEntity.ok(responseDTO);
        // return "redirect:/";
    }
}
