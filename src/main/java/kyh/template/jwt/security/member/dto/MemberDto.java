package kyh.template.jwt.security.member.dto;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;


public class MemberDto {

    @Setter
    @Getter
    @NoArgsConstructor
    public static class Post{

        @Email(message = "올바른 이메일 형식이여야 합니다")
        private String email;

        @NotBlank(message = "이름은 공백이 아니어야 합니다.")
        private String name;

        @NotBlank(message = "이름은 공백이 아니어야 합니다.")
        private String password;

}


    @Setter
    @Getter
    @NoArgsConstructor
    public static class Patch{

        @NotBlank(message = "이름은 공백이 아니어야 합니다.")
        private String name;

    }

    @Setter
    @Getter
    @NoArgsConstructor
    public static class Response{

        private Long memberId;

        private String email;

        private String name;

        List<String> roles = new ArrayList<>();

    }
}
