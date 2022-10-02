package kyh.template.jwt.security.member.entity;


import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@NoArgsConstructor
@Getter
@Setter
@Entity
public class Member{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long memberId;

    @Column(nullable = false, updatable = false, unique = true)
    private String email;

    @Column(length = 100, nullable = false)
    private String name;

    //+ (1) 비밀번호 추가
    @Column(length = 100, nullable = false)
    private String password;


    //+ (2) 권한 추가
    @ElementCollection(fetch = FetchType.EAGER)
    List<String> roles = new ArrayList<>();


}
