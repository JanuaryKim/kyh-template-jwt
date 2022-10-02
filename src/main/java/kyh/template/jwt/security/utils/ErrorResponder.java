package kyh.template.jwt.security.utils;

import com.google.gson.Gson;
import kyh.template.jwt.security.response.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ErrorResponder {
    public static void sendErrorResponse(HttpServletResponse response, HttpStatus status) throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);


        Gson gson = new Gson();
        ErrorResponse errorResponse = ErrorResponse.of(status);
        String errorContent = gson.toJson(errorResponse);

        response.getWriter().write(errorContent);
    }
}
