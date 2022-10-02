package kyh.template.jwt.security.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.security.SignatureException;
import kyh.template.jwt.security.jwt.JwtTokenizer;
import kyh.template.jwt.security.utils.CustomAuthorityUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Key;
import java.util.List;
import java.util.Map;


//OncePerRequestFilter : request당 단 1번만 수행되는 필터, 최초 request 들어 왔을때만, 유효한 jws인지 검증하면 되기 때문에 일반 필터를 만들지 않았음
//일반 필터는 들어올때, 나갈때 다 거침.


/** 해당 필터의 기능은 들어온 request에 달려있는 jwt을 검증하기 위한 용도 **/
@RequiredArgsConstructor
public class JwtVerificationFilter extends OncePerRequestFilter {

    private final JwtTokenizer jwtTokenizer;
    private final CustomAuthorityUtil customAuthorityUtil;


    /** 필터링 해야할 필요가 없는 필터인지 체크 **/
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {

        //Authorization 헤더가 존재하지 않는다는건, 아직 토큰을 받은 클라이언트가 아니기 때문에 토큰 검증 자체가 필요 없음
        String authorization = request.getHeader("Authorization");

        return authorization == null || !authorization.startsWith("Bearer");
    }

    /** 필터링 내용이 들어가는 메소드이다 **/
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //jws를 파싱하여 claims를 얻어 오는것만으로 내부적으로 토큰 유효기간검증, 권한, 변조 여부 다 검사함.

        try {
            Map<String, Object> claims = verifyJws(request);
            //Security Context에 저장
            setAuthenticationToSecurityContext(claims);
        } catch (SignatureException signatureException) {
            request.setAttribute("exception", signatureException);

        } catch (ExpiredJwtException expiredJwtException) {
            request.setAttribute("exception", expiredJwtException);
        } catch (Exception e) {
            request.setAttribute("exception",e);
        }
        //검증

        /** 주의 , 다음 필터 호출해줘야함. 그렇지 않으면 해당 필터에서 이후 처리가 끊켜버림!! **/
        filterChain.doFilter(request, response);
    }

    private void setAuthenticationToSecurityContext(Map<String, Object> claims) {
        String username = (String)claims.get("username");
        List<GrantedAuthority> authorityList = customAuthorityUtil.convertAuthority((List) claims.get("roles"));
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(username, null, authorityList);

        //Security Context에 Authentication 저장
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);

    }


    /** jws를 파싱해서 claim을 구해 오는것 자체가 내부적으로 검증처리를 해줌 (유효기간까지) **/
    private Map<String, Object> verifyJws(HttpServletRequest request) {
        String jws = request.getHeader("Authorization").replace("Bearer", "");
        String encodedBase64SecretKey = jwtTokenizer.encodeSecretKeyToBase64SecretKey(jwtTokenizer.getSecretKey());
        Key secretKey = jwtTokenizer.getKeyFromBase64EncodedKey(encodedBase64SecretKey);
        Jws<Claims> jwsClaims = jwtTokenizer.getClaims(jws, secretKey);
        Map<String,Object> claims = jwsClaims.getBody();

        return claims;
    }
}
