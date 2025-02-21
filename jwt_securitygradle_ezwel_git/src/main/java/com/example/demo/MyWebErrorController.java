package com.example.demo;

import java.net.URLDecoder;

import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;

@RestController
public class MyWebErrorController implements ErrorController {//오버라이딩할 메소드 없다.
	@RequestMapping("/error")
	String handleError(HttpServletRequest request) throws Exception {
		//다른 컨트롤러에서 오류 발생시 현재컨트롤러로 자동 forward
		//서버콘솔 출력 - 개발자용
		Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
		System.out.println("오류코드=" + status);
		System.out.println("오류메시지=" + request.getAttribute(RequestDispatcher.ERROR_MESSAGE) );
		//System.out.println("오류파일=" + request.getAttribute(RequestDispatcher.ERROR_REQUEST_URI) );
		//System.out.println("파라미터정보=" + request.getAttribute(RequestDispatcher.FORWARD_QUERY_STRING ));
		//if(request.getAttribute(RequestDispatcher.FORWARD_QUERY_STRING ) != null) {
		//	System.out.println("파라미터정보=" + 
		//	URLDecoder.decode((String)request.getAttribute(RequestDispatcher.FORWARD_QUERY_STRING ), "utf-8")
		//	);
		//}
		
		//System.out.println("요청방식=" + request.getMethod());	
		
		//http 프로토콜 파라미터 한글 - %16진수2자리....인코딩규칙 자동 
		// java.net.URLEncoder.encode("자바"); // %16진수2자리 -  구현
		//java.net.URLDecoder.decode("%16진수2자리"); // 자바 -  구현
		//400.jsp, 404, 405, 500
		return "errors/" + status.toString();  //브라우저 출력 - 사용자용
	}
	
}
