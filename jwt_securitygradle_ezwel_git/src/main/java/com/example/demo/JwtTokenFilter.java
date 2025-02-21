package com.example.demo;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

//@Configuration
@RequiredArgsConstructor
public class JwtTokenFilter extends OncePerRequestFilter{

	final String  mykey ;
	final PasswordEncoder encoder;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

    	String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
    	System.out.println("JwtTokenFilter(헤더값확인용출력): "+authorizationHeader);

        if(authorizationHeader == null) {
  		  System.out.println("JwtTokenFilter(request.getCookies()확인용출력1): "+request.getCookies());
  	      if(request.getCookies() == null) {
  	          filterChain.doFilter(request, response);
  	          return;
  	      }
  	      System.out.println("JwtTokenFilter(request.getCookies()확인용출력2): "+request.getCookies()[0].getName());
  	      Cookie jwtTokenCookie = Arrays.stream(request.getCookies())
				.filter(cookie -> cookie.getName().equals("jwtcookie"))
  	        .findFirst()
  	        .orElse(null);
  	     
	      if(jwtTokenCookie == null) {
	          filterChain.doFilter(request, response);
	          return;
	      }

	      String jwtToken = jwtTokenCookie.getValue();
	      System.out.println("JwtTokenFilter(쿠키값확인용출력): " + jwtToken);
	      authorizationHeader = "Bearer " + jwtToken;
         }//if(authorizationHeader == null) end
        
        if(!authorizationHeader.startsWith("Bearer ") ) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authorizationHeader.split(" ")[1];

        if(JwtTokenUtil.isExpired(token, mykey)) {
            filterChain.doFilter(request, response);
            return;
        }

        System.out.println(encoder.encode("1111"));
        System.out.println(encoder.encode("1111"));
        System.out.println(encoder.encode("1111"));
        
        String loginId = JwtTokenUtil.getLoginId(token, mykey);
        Users loginuser = new Users();
        loginuser.setLoginid("user");
        loginuser.setPassword(encoder.encode("1111"));
        loginuser.setName("홍길동");
        loginuser.setRole(UserRole.USER.name());

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
				loginuser/* .getName() */, null, List.of(new SimpleGrantedAuthority(loginuser.getRole())));
       SecurityContextHolder.getContext().setAuthentication(authenticationToken);
              
        filterChain.doFilter(request, response);
        
	}
	
}



