package com.example.demo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

@RestController
public class UserController {
	@Value("${jwt.secretkey}")
	String mykey ;//토큰값 복호화 key 필요-github

	@RequestMapping("/loginjwt/{id}/{pw}")
	@CrossOrigin(origins="http://localhost:4000")
	public String getUserJwt(@PathVariable("id") String id, @PathVariable("pw") String pw) {
		if(id.equals("user") && pw.equals("1111")) {
			System.out.println(mykey + " : jwt key 확인중");
			//세션생성-id저장(서버측)
	        long expiredTimeMs = 60 * 60 * 1000;//1시간
	        return JwtTokenUtil.createToken(id, mykey, expiredTimeMs);
	        //클라이언트 전송(그다음 요청시 서버로 전달되기 위해선 클라이언트측 지속 저장)
	        //js(2> cookie, 1> localStorage)
		}else {
				return "id나 pw 중 하나 비정상";
		}
	}
	
	@RequestMapping("/loginjwtheader/{id}/{pw}")  //요청객체(요청헤더(ip,  브라우저)+요청바디) / 응답객체(응답헤더+응답바디)
	@CrossOrigin(origins="http://localhost:4000", exposedHeaders = "Authorization")
	public ResponseEntity<String> getUserJwtHeader(@PathVariable("id") String id, @PathVariable("pw") String pw) {
		if(id.equals("user") && pw.equals("1111")) {
			System.out.println(mykey + " : jwt key 확인중");
	        long expiredTimeMs = 60 * 60 * 1000;//1시간
	        String genToken = JwtTokenUtil.createToken(id, mykey, expiredTimeMs);
	        //응답 헤더 AUTHORIZATION-jwt "Bearer"
	        HttpHeaders httpheaders = new HttpHeaders();
	        httpheaders.add("Authorization", "Bearer " + genToken);
	        //또는 응답 바디 
	        String tokenJson = "{\"jwtToken\":\"Bearer " + genToken + "\"}";
	        return new ResponseEntity<String>(tokenJson, httpheaders, HttpStatus.OK); //200 OK

		}else {
				return new ResponseEntity<String>("id나 pw 중 하나 비정상", HttpStatus.OK);
		}
	}

	//http://localhost:8080/loginjwtcookie/user/1111 -> 
	//http://localhost:8080/xxxx
	@RequestMapping("/loginjwtcookie/{id}/{pw}")
	@CrossOrigin(origins="http://localhost:4000" , allowCredentials = "true")
	public String getUserJwtCookie
	(@PathVariable("id") String id, @PathVariable("pw") String pw, HttpServletResponse response) {
		if(id.equals("user") && pw.equals("1111")) {
			System.out.println(mykey + " : jwt key 확인중");
			//세션생성-id저장(서버측)
	        long expiredTimeMs = 60 * 60 * 1000;//1시간
	        String genToken = JwtTokenUtil.createToken(id, mykey, expiredTimeMs);
	        
	        Cookie cookie = new Cookie("jwtcookie", genToken);
	        cookie.setPath("/");
	        cookie.setMaxAge(60*60);//1시간
	        response.addCookie(cookie);//클라이언트 전송
	        return "로그인 성공";
	        
		}else {
				return "id나 pw 중 하나 비정상";
		}
	}
	
	//http://localhost:8080/loginjwtheader/user/1111 -> localStorage 저장
	//http://localhost:8080/userinfo?jwt전달
	@RequestMapping("/userinfo")
	@CrossOrigin(origins="http://localhost:4000", allowCredentials = "true")
	public String userinfo(Authentication auth, @AuthenticationPrincipal Users user) {
	    	System.out.println("/loginsuccess : " + user);
			System.out.println("/loginsuccess : " + SecurityContextHolder.getContext().getAuthentication());
			System.out.println(auth.getName() + ":" + auth.isAuthenticated() + ":" + auth.getPrincipal());
			//System.out.println(user.getUsername() + ":" + user.getAuthorities());
	    	//return user.getName() + " 회원님 " + user.getRole() + "  권한입니다.";
	    	return auth.getName() + " 회원님 " + auth.getAuthorities() + "  권한입니다.";
	}
	
	@RequestMapping("/logoutjwtcookie") 
	@CrossOrigin(origins="http://localhost:4000", allowCredentials = "true")
	public String logout(HttpServletResponse response) {
		//Cookie삭제
        Cookie cookie = new Cookie("jwtcookie", null);
        cookie.setMaxAge(0);//즉각적 삭제
        response.addCookie(cookie);//클라이언트 전송
		return "로그아웃하셨습니다.";

	}
	
}
