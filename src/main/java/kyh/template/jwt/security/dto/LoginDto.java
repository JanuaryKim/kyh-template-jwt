package kyh.template.jwt.security.dto;

import lombok.Getter;


//클라이언트가 전송한 Username/Password 정보를 Security Filter 에서 사용할 수 있도록 역직렬화(Deserialization)하기 위한 DTO
@Getter
public class LoginDto {

    private String username;
    private String password;

}
