package kyh.template.jwt.security.member.controller;


import kyh.template.jwt.security.member.dto.MemberDto;
import kyh.template.jwt.security.member.entity.Member;
import kyh.template.jwt.security.member.mapper.MemberMapper;
import kyh.template.jwt.security.member.service.MemberService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import javax.validation.constraints.Positive;

@Validated
@RequestMapping("/v12/members")
@RestController
public class MemberController {

    private final MemberService memberService;
    private final MemberMapper memberMapper;


    public MemberController(MemberService memberService, MemberMapper memberMapper) {
        this.memberService = memberService;
        this.memberMapper = memberMapper;
    }

    @PostMapping
    public ResponseEntity postMember(@Valid @RequestBody MemberDto.Post memberDto) {

        Member member = memberMapper.MemberPostDtoToMember(memberDto);
        Member createdMember = memberService.createMember(member);
        MemberDto.Response response = memberMapper.MemberToMemberResponseDto(createdMember);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }



    @GetMapping("/{member-id}")
    public ResponseEntity getMember(@Positive @PathVariable("member-id") long memberId) {
        Member member = memberService.findMember(memberId);
        MemberDto.Response response = memberMapper.MemberToMemberResponseDto(member);

        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}
