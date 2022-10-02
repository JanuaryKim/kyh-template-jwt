package kyh.template.jwt.security.member.service;

import kyh.template.jwt.security.member.entity.Member;
import kyh.template.jwt.security.utils.CustomAuthorityUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Collection;

/** 인증을 시도하는 Aunthentication의 username으로 해당 유저를 조회하는 **/
@RequiredArgsConstructor
@Component
public class MemberDetailsService implements UserDetailsService {

    private final MemberService memberService;
    private final CustomAuthorityUtil authorityUtil;

    /** username을 조회하여, 인증된 Authentication을 만들기 위해 필요한 UserDetails를 생성하는 메소드 **/
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Member findMember = memberService.verifyExistsMemberByEmail(username);

        return new CustomUserDetails(findMember);
    }



    private class CustomUserDetails extends Member implements UserDetails{

        public CustomUserDetails(Member member) {

            setMemberId(member.getMemberId());
            setEmail(member.getEmail());
            setName(member.getName());
            setPassword(member.getPassword());
            setRoles(member.getRoles());
        }

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return authorityUtil.convertAuthority(getRoles());
        }

        @Override
        public String getPassword() {
            return super.getPassword();
        }

        @Override
        public String getUsername() {
            return getEmail();
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return true;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return true;
        }
    }
}
