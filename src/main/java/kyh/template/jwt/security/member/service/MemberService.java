package kyh.template.jwt.security.member.service;

import kyh.template.jwt.security.exception.BusinessLogicException;
import kyh.template.jwt.security.exception.ExceptionCode;
import kyh.template.jwt.security.member.dto.MemberDto;
import kyh.template.jwt.security.member.entity.Member;
import kyh.template.jwt.security.repository.MemberRepository;
import kyh.template.jwt.security.utils.CustomAuthorityUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@RequiredArgsConstructor
@Transactional
@Service
public class MemberService {

    private final MemberRepository repository;
    private final CustomAuthorityUtil authorityUtil;
    private final PasswordEncoder passwordEncoder;

    public Member createMember(Member member) {

        verifyValidEmail(member.getEmail());

        member.setRoles(authorityUtil.createAuthority(member.getEmail()));
        member.setPassword(passwordEncoder.encode(member.getPassword()));


        Member savedMember = repository.save(member);

        return savedMember;
    }

    public Member findMember(long memberId) {

        Member findMember = verifyExistsMemberById(memberId);

        return findMember;
    }



    /** 존재하는 멤버인지 검증 **/
    public Member verifyExistsMemberByEmail(String email) {

        return repository.findByEmail(email).orElseThrow(
                ()-> {throw new BusinessLogicException(ExceptionCode.MEMBER_NOT_FOUND);});
    }

    /** 존재하는 멤버인지 검증 **/
    public Member verifyExistsMemberById(long memberId) {

        return repository.findById(memberId).orElseThrow(
                ()-> {throw new BusinessLogicException(ExceptionCode.MEMBER_NOT_FOUND);});
    }

    /** 가입이 가능한 멤버인지 검증 **/
    public void verifyValidEmail(String email) {

        repository.findByEmail(email).ifPresent(
                member -> {throw new BusinessLogicException(ExceptionCode.MEMBER_EXISTS);});

    }

}
