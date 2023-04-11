package shop.mtcoding.security_app.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

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
                // 단,successHandler이 있으면 defaultSuccessUrl 실행되지 않음
                // 경로 설정하고 싶으면 resp.sendRedirect("경로") 추가해주면 됨
                .successHandler((req, resp, Authentication) -> {
                    // log 알려주기 전까지 본 코드에 '디버그' 키워드 붙이기
                    System.out.println("디버그: 로그인이 완료되었습니다");
                    resp.sendRedirect("/");
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
                    .access("hasRole('ADMIN') or hasRole('MANAGER')")
                    // admin 경로는 ADMIN role(권한) 필요
                    .antMatchers("/admin/**")
                    .hasRole("ADMIN")
                    .anyRequest().permitAll();
        });
        // filter에 SecurityFilterChain가 씌워진 것?
        return http.build();
    }

    // cors 설정
    public CorsConfigurationSource configurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedHeader("*");
        // 필수
        configuration.addAllowedMethod("*");
        // GET, POST, PUT, DELETE (Javascript 요청 허용)
        configuration.addAllowedOriginPattern("*");
        // 모든 IP 주소 허용 (프론트 앤드 IP만 허용 react)
        // app은 논외 : javascript 사용하지 않기 때문
        // 근데 웹을 flutter로 생성 해도 javascript로 바뀌기 때문에 flutter 프론트 ip 허용 해주어야 함
        configuration.setAllowCredentials(true);
        // 클라이언트에서 쿠키 요청 허용
        configuration.addExposedHeader("Authorization");
        // 옛날에는 디폴트 였다. 지금은 아닙니다.
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
