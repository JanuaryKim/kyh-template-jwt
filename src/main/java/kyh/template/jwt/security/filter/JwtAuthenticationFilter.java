package kyh.template.jwt.security.filter;

import kyh.template.jwt.security.dto.LoginDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import kyh.template.jwt.security.jwt.JwtTokenizer;
import kyh.template.jwt.security.member.entity.Member;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;


//SecurityFilterChain으로 인해 만들어진 필터로, ID, PWD 방식의 로그인할때 작동되는 UsernamePasswordAuthenticationFilter 클래스를 상속 하여 필터 생성

/** 해당 필터의 기능은 로그인 요청한 유저의 인증처리를 해주기 위한 용도의 클래스(토큰 발행) **/
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenizer jwtTokenizer;


    /** 아직 검증되지 않은 Authentication을 만들어서, 검증 한후 검증 된 Authentication을 리턴 **/
    @SneakyThrows //예외처리를 명시적으로 해주는 애노테이션
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {


        //Username과 Password를 DTO 클래스로 역직렬화(Deserialization)하기 위해 ObjectMapper 인스턴스 생성
        ObjectMapper objectMapper = new ObjectMapper();

        //request로 들어온 Username과 Password를 LoginDto 객체로 만듦 (역 직렬화)
        LoginDto loginDto = objectMapper.readValue(request.getInputStream(), LoginDto.class);

        //리턴할 Authentication 구현 객체 생성
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginDto.getUsername(),loginDto.getPassword());

        //검증 과정 거친 뒤 인증된 Authentication 리턴
        return authenticationManager.authenticate(authenticationToken);
    }


    // 클라이언트의 인증 정보를 이용해 인증에 성공할 경우 내부적으로 호출되는 메소드
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult) throws IOException, ServletException {

        Member member = (Member) authResult.getPrincipal();

        //액세스 토큰 생성
        String accessToken = delegateAccessToken(member);

        //리프레쉬 토큰 생성
        String refreshToken = delegateRefreshToken(member);

        //헤더에 액세스, 리프레쉬 토큰 추가
        response.setHeader("Authorization", "Bearer" + accessToken);
        response.setHeader("Refresh", refreshToken);

        /** 반드시 추가할것!!!, 해당 소스를 추가하지 않으면 내부적으로 등록한 핸들러의 핸들러 메소드까지 도달하지 않음 **/
        this.getSuccessHandler().onAuthenticationSuccess(request, response, authResult);
    }

    //액세스 토큰을 대리하여 생성해주는 메소드로, 토큰 생성에 필요한 데이터 취합하여 여기서도 jwtTokenizer에게 실질적인 토큰 생성을 위임
    private String delegateAccessToken(Member member) {

        //클레임즈 생성
        Map<String, Object> claims = new HashMap<>();
        claims.put("username", member.getEmail());
        claims.put("roles", member.getRoles());

        //서브젝트
        String subject = member.getEmail();

        String encodedSecretKey = jwtTokenizer.encodeSecretKeyToBase64SecretKey(jwtTokenizer.getSecretKey());
        Key keyFromBase64EncodedKey = jwtTokenizer.getKeyFromBase64EncodedKey(encodedSecretKey);
        Date tokenExpiration = jwtTokenizer.getTokenExpiration(30);

        //토큰 생성
        String accessToken = jwtTokenizer.generateAccessToken(
                claims, subject, tokenExpiration, keyFromBase64EncodedKey);

        return accessToken;
    }

    //리프레쉬 토큰을 대리하여 생성해주는 메소드로, 토큰 생성에 필요한 데이터 취합하여 여기서도 jwtTokenizer에게 실질적인 토큰 생성을 위임
    private String delegateRefreshToken(Member member) {
        String subject = member.getEmail();
        Date expiration = jwtTokenizer.getTokenExpiration(jwtTokenizer.getRefreshTokenExpirationMinutes());
        String encodedSecretKey = jwtTokenizer.encodeSecretKeyToBase64SecretKey(jwtTokenizer.getSecretKey());

        Key key = jwtTokenizer.getKeyFromBase64EncodedKey(encodedSecretKey);

        String refreshToken = jwtTokenizer.generateRefreshToken(subject, expiration, key);

        return refreshToken;
    }



}
