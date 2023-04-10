package shop.mtcoding.security_app.core.auth;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.Getter;
import shop.mtcoding.security_app.model.User;

@Getter
// UserDetails를 implements하는 건 규칙
public class MyUserDetails implements UserDetails {

    private User user;

    public MyUserDetails(User user) {
        this.user = user;
    }

    // 권한이 필요한 요청이 있을 때 사용 - SecurityConfig에서 설정한 hasRole과 비교
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(() -> "ROLE_" + user.getRole());
        return authorities;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    // 계정이 만료되지 않았는지 유무 - true일 경우 만료되지 않음 의미
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    // 계정이 잠겨있는지 유무 - ex) 비밀번호 n번 틀리면 로그인 접근 제한
    // true일 때 잠겨 있지 않음 의미
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 계정의 패스워드가 만료됐는지 - true일 때 만료되지 않음 의미
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // user가 활성화 상태인지 아닌지
    @Override
    public boolean isEnabled() {
        return user.getStatus();
    }

}
