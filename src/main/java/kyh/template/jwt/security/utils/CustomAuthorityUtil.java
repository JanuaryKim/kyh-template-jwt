package kyh.template.jwt.security.utils;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class CustomAuthorityUtil {

    @Value("${mail.address.admin}")
    private String adminEmail;

    private final List<String> ADMIN_ROLE = List.of("ADMIN","USER");
    private final List<String> USER_ROLE = List.of("USER");

    //DB상에 있는 권한을 UserDetails가 쓸 수 있는 권한으로 변환
    public List<GrantedAuthority> convertAuthority(List<String> role) {
        return role.stream().map(str->{
            return new SimpleGrantedAuthority("ROLE_" + str);
        }).collect(Collectors.toList());
    }

    public List<String> createAuthority(String email) {
        if(email.equals(adminEmail))
            return ADMIN_ROLE;

        return USER_ROLE;
    }

}
