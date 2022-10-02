package kyh.template.jwt.security.member.mapper;


import kyh.template.jwt.security.member.dto.MemberDto;
import kyh.template.jwt.security.member.entity.Member;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface MemberMapper {

    Member MemberPostDtoToMember(MemberDto.Post memberPostDto);
    MemberDto.Response MemberToMemberResponseDto(Member member);
}
