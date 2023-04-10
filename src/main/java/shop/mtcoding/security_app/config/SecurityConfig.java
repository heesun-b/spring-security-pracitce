package shop.mtcoding.security_app.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // csrf = 잘못된 경로를 막는 것, disable 해주는 이유는 postman 테스트 위해
        // csr (외부 접근) 할 떄
        http.csrf().disable();

        // 2. form 로그인 설정
        http.formLogin()
                .loginPage("/loginForm")
                // form 태그 input-name 설정 가능
                .usernameParameter("username")
                .passwordParameter("password")
                // ProcessingUrl는 무조건 post, x-www-FormUrlEncoded
                .loginProcessingUrl("/login")
                // defaultSuccessUrl는 login 성공 시 이동될 페이지 경로
                .defaultSuccessUrl("/")
                // .successHandler(null) - 로그인 성공 시 Handler
                .successHandler((req, resp, Authentication) -> {
                    // log 알려주기 전까지 본 코드에 '디버그' 키워드 붙이기
                    System.out.println("디버그: 로그인이 완료되었습니다");
                })
                // .failureHandler(null) - 로그인 실패 시 Handler
                .failureHandler((req, resp, ex) -> {
                    System.out.println("디버그 : 로그인 실패 " + ex.getMessage());
                });

        // 3. 인증, 권한 필터 설정
        http.authorizeRequests((authorize) -> {
            // users/** 경로는 인증 필요
            authorize.antMatchers("/users/**")
                    .authenticated()
                    // manager 경로는 MANAGER 혹은 admin role(권한) 필요
                    .antMatchers("/manager/**")
                    .access("hasRole('ADMIN') or ('MANAGER')")
                    // admin 경로는 ADMIN role(권한) 필요
                    .antMatchers("/admin/**")
                    .hasRole("ADMIN")
                    .anyRequest().permitAll();
        });
        // filter에 SecurityFilterChain가 씌워진 것?
        return http.build();
    }
}
