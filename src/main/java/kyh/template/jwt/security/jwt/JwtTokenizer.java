package kyh.template.jwt.security.jwt;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

/** 토큰과 관련된 실질적인 역할을 하는 클래스 **/
@Getter
@Component
public class JwtTokenizer {

    @Getter
    @Value("${jwt.secret-key}")
    private String secretKey;

    @Getter
    @Value("${jwt.access-token-expiration-minutes}")
    private int accessTokenExpirationMinutes;

    @Getter
    @Value("${jwt.refresh-token-expiration-minutes}")
    private int refreshTokenExpirationMinutes;

    /** 실질적으로 액세스 토큰을 생성하는 메소드 **/
    public String generateAccessToken(Map<String,Object> claims,
                                      String subject,
                                      Date expiration,
                                      Key secretKey) {

        return Jwts.builder().setClaims(claims).setSubject(subject)
                .setIssuedAt(Calendar.getInstance().getTime())
                .setExpiration(expiration).signWith(secretKey).compact();
    }

    /** 실질적응로 리프레쉬 토큰을 생성하는 메소드 **/
    public String generateRefreshToken(String subject,
                                      Date expiration,
                                      Key secretKey) {

        return Jwts.builder().setSubject(subject)
                .setIssuedAt(Calendar.getInstance().getTime())
                .setExpiration(expiration).signWith(secretKey).compact();
    }


    //평문 상태의 시크릿키를 그대로 암호화 과정에 사용하는것은,
    //일반적으로 암호화 하는 작업에는 바이너리 형태의 키가 사용된다는 점과 맞지 않으므로 한번 인코딩하여 사용하기 사용되는 메소드
    /** 시크릿키를 바이트형태로 변환한뒤 Base64로 인코딩하는 메소드 **/
    public String encodeSecretKeyToBase64SecretKey(String secretKey) {

        //해당 String 평문을 UTF-8 캐릭터셋 으로 바이트배열로 변환하여 인코딩 (왜냐하면 재정의된 encode()메소드가 byte[] 배열만 받음)
        return Encoders.BASE64.encode(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    /** 토큰의 만료시간 값 만들어서 리턴, 인자는 추가할 시간 (분단위) **/
    public Date getTokenExpiration(int expirationMinutes) {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MINUTE, expirationMinutes);
        return calendar.getTime();
    }

    /**
     * 토큰에서 claim 부분을 얻어오기 + 검증 메소드, 만약 유효기간이 지났을 경우 해당 메소드에서 파싱하면서 exception이 발생,
     **/
    public Jws<Claims> getClaims(String jws, Key secretKey) {


        Jws<Claims> claims = Jwts.parserBuilder() //Jwts를 파싱하는 빌더 생성
                .setSigningKey(secretKey) //시크릿키 셋팅
                .build() //파싱 빌더 빌드 (최종 객체 생성)
                .parseClaimsJws(jws); //만들어진 객체에서 claims 부분만 파싱 (jws 매개변수)

        return claims;
    }

    /** Base64로 인코딩된 시크릿키를 다시 디코딩하여 실제 시크릿키 객체를 만드는 메소드 **/
    public Key getKeyFromBase64EncodedKey(String base64EncodedSecretKey) {
        byte[]keyBytes = Decoders.BASE64.decode(base64EncodedSecretKey); //
        Key secretKey = Keys.hmacShaKeyFor(keyBytes); //암호화 알고리즘을 써서 시크릿키 객체를 생성
        return secretKey;

    }

}
