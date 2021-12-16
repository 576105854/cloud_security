package com.zr.security.security;

import com.zr.utils.utils.R;
import com.zr.utils.utils.ResponseUtil;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 退出处理器
 */
public class TokenLogoutHandler implements LogoutHandler {
    private TokenManager tokenManager;
    private RedisTemplate redisTemplate;

    public TokenLogoutHandler(TokenManager tokenManager, RedisTemplate redisTemplate) {
        this.tokenManager = tokenManager;
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse httpServletResponse, Authentication authentication) {
        //1.从heaer里获取token
        //2.token不为空，移除token,从redis删除token
        String token = request.getHeader("token");
        if(token != null){
            //移除
            tokenManager.removeToken(token);
            //从token获取用户名
            String userInfoFromToken = tokenManager.getUserInfoFromToken(token);
            redisTemplate.delete(userInfoFromToken);
        }

        ResponseUtil.out(httpServletResponse, R.ok());
    }
}
