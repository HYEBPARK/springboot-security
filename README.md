## DAY 1
### 🎁 MISSION
### AnonymousAuthenticationFilter
- 인증 정보가 존재하지 않을 경우 익명 사용자용 익명 객체를 생성한다.
- isAnonymous()와 isAuthenticated()를 통해 인증 여부를 검사
- 인증객체를 세션에 저장하지 않음 
### ExceptionTranslationFilter
- 사용자의 요청을 받을 때, 그 다음 필터로 그 요청을 전달할 때 try-catch로 감싸서  FilterSecurityInterceptor 를 호출하고 있고, 해당 필터에서 생기는 인증 및 인가 예외는
  ExceptionTranslationFilter로 throw 하고 있다.
### 대칭 키 암호화, RSA 암호화에 대해 정리해보기
- 대칭 키 암호화 : 암호화와 복호화에 사용하는 키가 같은 암호화 알고리즘
   - 장점 : 빠르다. 
   - 단점 : 비밀키가 유출되면 해킹 위험 
- RSA 암호화 : 비대칭 키 암호화로 암복호화에 사용하는 키가 다르다.
   - 가장 널리 쓰이고 있는 공개키 알고리즘
   - 안정성 검증, 이해와 구현이 쉽다.
### SSL 인증서를 직접 생성해보고, Spring Boot 프로젝트에 적용해보기