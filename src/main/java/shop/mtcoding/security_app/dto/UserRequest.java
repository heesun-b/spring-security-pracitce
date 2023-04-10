package shop.mtcoding.security_app.dto;

import lombok.Getter;
import lombok.Setter;
import shop.mtcoding.security_app.model.User;

public class UserRequest {

    @Getter
    @Setter
    public static class JoinDTO {
        private String username;
        private String password;
        private String email;
        private String role;

        // insert 하는 것들만 만들면 됨
        public User toEntity() {
            return User.builder()
                    .username(username)
                    .password(password)
                    .email(email)
                    .role(role)
                    .build();
        }
    }
}
