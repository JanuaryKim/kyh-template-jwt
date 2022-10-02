package kyh.template.jwt.security.config;

import kyh.template.jwt.security.filter.JwtAuthenticationFilter;
import kyh.template.jwt.security.filter.JwtVerificationFilter;
import kyh.template.jwt.security.handler.MemberAccessDeniedHandler;
import kyh.template.jwt.security.handler.MemberAuthenticationEntryPoint;
import kyh.template.jwt.security.handler.filter_handler.MemberAuthenticationFailureHandler;
import kyh.template.jwt.security.handler.filter_handler.MemberAuthenticationSuccessHandler;
import kyh.template.jwt.security.jwt.JwtTokenizer;
import kyh.template.jwt.security.utils.CustomAuthorityUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

/** Spring Security에 필요한 요소들을 빈으로 등록하는 설정 클래스 **/
@RequiredArgsConstructor
@Configuration
public class SecurityConfiguration {

    private final JwtTokenizer jwtTokenizer;
    private final CustomAuthorityUtil customAuthorityUtil;


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .headers().frameOptions().sameOrigin()//H2를 위해 같은 도메인에서는 frame 같은 태그에서 uri로 접속 요청 들어 오는것 허용
                .and()
                .csrf().disable()
                .cors(withDefaults()) // CORS 관련 필터를 등록하기 위해, 기본적으로 corsConfigurationSource 이라는 빈을 등록
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) //세션을 생성하지 않도록 정책 지정
                .and()
                .formLogin().disable() //폼 로그인 형식 사용 안함
                //HTTP Basic 인증은 request를 전송할 때 마다 Username/Password 정보를 HTTP Header에 실어서 인증을 하는 방식이므로, 토큰을 구현중인 현재프로젝트에선 사용 안함.
                .httpBasic().disable()
                .apply(new CustomFilterConfigurer())  //Spring Security의 Configuration (설정 정보) 을 내가 직접 등록 할것이기 때문에
                .and()
                .exceptionHandling() //Exception 핸들링 처리 설정 시작
                .accessDeniedHandler(new MemberAccessDeniedHandler()) //권한이 없는 리소스에 접근 했을 경우에 처리하는 핸들러 (User가 Admin 리소스를 접근)
                .authenticationEntryPoint(new MemberAuthenticationEntryPoint()) ///인증 과정에서 AuthenticationException 발생시 처리하는 핸들러, SignatureException, ExpiredJwtException
                .and()
                .authorizeHttpRequests(authorize -> authorize
                        .antMatchers(HttpMethod.POST, "/v12/members").permitAll()
                        .antMatchers(HttpMethod.GET, "/v12/members").hasRole("ADMIN")
                        .antMatchers(HttpMethod.GET, "/v12/members/**").hasRole("USER")
                        .anyRequest().permitAll()
                );
        return http.build();
    }


    //비밀번호 암호화를 위해
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    //Spring Security 의 Configuration(설정자)을 커스터마이징.
    //해당 설정자에서 필터등록, 보안관련 각종 설정을 할 수 있다.
    //이렇게 만들어지는 설정자를 최종적으로 HttpSecurity에 등록하여야 적용이 된다.
    public class CustomFilterConfigurer extends AbstractHttpConfigurer<CustomFilterConfigurer, HttpSecurity> {

        //실질적으로 커스터마이킹 하는 메소드
        @Override
        public void configure(HttpSecurity builder) throws Exception {

            //AuthenticationManager 객체 얻기, AuthenticationManager : 인증에 대한 처리를 총괄하는 클래스
            //getSharedObject() 를 통해서 Spring Security의 설정을 구성하는 SecurityConfigurer 간에 공유되는 객체를 얻을 수 있음
            AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);

            //JwtAuthenticationFilter : 인증처리 필터
            //상속받아 재정의한 필터 객체, 필요한 객체들 DI
            JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager, jwtTokenizer);

            //디폴트 request URL인 “/lo gin”을 “/v11/auth/login”으로 변경,
            //해당 url로 요청이 들어오면 스프링 내부적으로 인증처리라는것을 인지해서 JwtAuthenticationFilter 필터의 처리를 거친다.
            //그러나 해당 url이 아니라면 JwtAuthenticationFilter 필터의 필터링을 건너뛴다!!
            jwtAuthenticationFilter.setFilterProcessesUrl("/v12/auth/login");

            //인증 성공시 작동되는 핸들러, JwtAuthenticationFilter 필터에서 성공시 호출되는 메소드보다 후에 호출된다
            jwtAuthenticationFilter.setAuthenticationSuccessHandler(new MemberAuthenticationSuccessHandler());

            //인증 실패시 작동되는 핸들러
            jwtAuthenticationFilter.setAuthenticationFailureHandler(new MemberAuthenticationFailureHandler());

            //JwtVerificationFilter : 토큰의 유효성 검증 필터
            //상속받아 재정의한 필터 객체, 필요한 객체들 DI
            JwtVerificationFilter jwtVerificationFilter = new JwtVerificationFilter(jwtTokenizer, customAuthorityUtil);

            //필터 등록 순서 중요
            //Filter를 실질적으로 Spring Security Filter Chain에 추가
            builder.addFilter(jwtAuthenticationFilter)
                    //검증 request시 넘어 온 jwt의 검증 필터 추가, addFilterAfter : 2번째의 인자인 필터의다음으로 필터를추가함
                    .addFilterAfter(jwtVerificationFilter, JwtAuthenticationFilter.class);
        }
    }

}

