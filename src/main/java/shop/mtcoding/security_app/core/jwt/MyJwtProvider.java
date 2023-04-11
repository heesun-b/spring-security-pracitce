package shop.mtcoding.security_app.core.jwt;

import java.util.Date;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;

import shop.mtcoding.security_app.model.User;

public class MyJwtProvider {

    private static final String SUBJECT = "jwtstudy";
    private static final int EXP = 1000 * 60 * 60;
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER = "Authorization"; // header는 응답할 때 써야하므로 public
    private static final String SECRET = System.getenv("HS512_SECRET"); // secret은 실제 사용할 땐 os 환경변수로 빼기

    public static String create(User user) {
        String jwt = JWT
                .create()
                .withSubject(SUBJECT) // token 제목
                .withExpiresAt(new Date(System.currentTimeMillis() + EXP)) // token 만료 시간, 예제는 7일
                .withClaim("id", user.getId()) // user의 primary key
                .withClaim("role", user.getRole()) // user의 primary key
                .sign(Algorithm.HMAC512(SECRET));
        return TOKEN_PREFIX + jwt; // 이건 프로토콜
    }

    public static DecodedJWT verify(String jwt) throws SignatureVerificationException, TokenExpiredException {
        // try catch 안 하는 이유 - handler 처리를 못 해서
        DecodedJWT decodeJwt = JWT.require(Algorithm.HMAC512(SECRET)).build().verify(jwt);
        return decodeJwt;
    }
}