import com.google.gson.Gson;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.codehaus.jackson.map.ObjectMapper;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

@Controller
@RequestMapping(value = "/join")
public class AppleLogin {
    private final Logger logger = LoggerFactory.getLogger(this.getClass()); 
    private static ObjectMapper objectMapper = new ObjectMapper();

    /**
     * 1.개요 : 애플 로그인 연동
     * 2.처리내용 : 애플 인증 URL로 리다이렉트 연결
     * 				1. 애플에서 code 정보를 리턴한다.
     *              2. 리턴된 code키를 이용하여 토큰 검증 및 사용자 정보 발급한다.
     *              3. 인증 토큰을 이용하여 사용자 정보를 조회한다.
     *              4. 정보를 생성하여 DB에 저장
     *              5. 로그인 여부를 판단하여 세션 정보를 생성한다.
     */
    @RequestMapping(value = "/getAppleAuthUrl", method = RequestMethod.GET)
    public @ResponseBody String getAppleAuthUrl(HttpServletRequest request) throws Exception {

        //response_type : code나 code와 id_token 값만 지정가능.(필수)
        //scope : 사용자 정보 요청값. name과 email만 가능.
        //response_mode : 응답 유형. 쿼리 파람형식 또는 form post 유형 지정가능.
        String reqUrl =
                "https://appleid.apple.com"
                + "/auth/authorize?client_id="
                + "apple_client_id" //Services Identifier
                + "&redirect_uri="
                + "/account/oauth_apple"
                + "&response_type=code%20id_token&scope=email%20name&response_mode=form_post";

        return reqUrl;
    }

    @RequestMapping(value = "/oauth_apple", method = {RequestMethod.GET, RequestMethod.POST})
    public String oauth_apple(@RequestParam(value = "code", required= false) String code, Model model, HttpServletRequest request, HttpSession session, HttpServletResponse response) throws Exception {

        //--- 2. 토큰 검증 및 사용자 정보 발급한다.
        logger.error("========code============" + code);

        if(code == null) {
            logger.error("========애플로그인 취소============" + code);
            return "/index";
        }

        String domainurl = "domainurl";

        //애플 인증키 위치 (애플인증키.p8)
        String sns_apple_key_path = "D:/appleKey/애플인증키.p8";

        logger.error("========sns_apple_key_path============" + sns_apple_key_path);

        String teamId = "apple_team_id";
        String clientId = "apple_client_id"; //Services Identifier";
        String keyId = "apple_key_id";
        String keyPath = sns_apple_key_path;
        String authUrl = "https://appleid.apple.com";

        logger.error("========sns_apple_team_id============" + teamId);
        logger.error("========sns_apple_client_id============" + clientId);
        logger.error("========sns_apple_key_id============" + keyId);
        logger.error("========sns_apple_key_path============" + keyPath);
        logger.error("========sns_apple_auth_url============" + authUrl);

        String client_secret = "";

        //애플 로그인에 사용될 토큰 서명 알고리즘 ES256
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(keyId).build();
        JWTClaimsSet claimsSet = new JWTClaimsSet();
        Date now = new Date();

        claimsSet.setIssuer(teamId);
        claimsSet.setIssueTime(now); //토근 생성 시간
        claimsSet.setExpirationTime(new Date(now.getTime() + 3600000)); //토큰 만료 시간
        claimsSet.setAudience(authUrl); // 유효성 검사 서버 (https://appleid.apple.com)
        claimsSet.setSubject(clientId);

        SignedJWT jwt = new SignedJWT(header, claimsSet);

        // 인증키 파일 읽어오기 s
        //Resource resource = new ClassPathResource(keyPath);
        byte[] content = null;

        try (
                // 배포시 파일을 찾지 못함.
                //--- 1.
                //InputStream keyInputStream = resource.getInputStream();
                //InputStreamReader keyReader = new InputStreamReader(keyInputStream);
                //PemReader pemReader = new PemReader(keyReader)
                //--- 2.
                //FileReader keyReader = new FileReader(resource.getFile());
                //PemReader pemReader = new PemReader(keyReader)

                //--- 3.
                FileReader keyReader = new FileReader(keyPath);
                PemReader pemReader = new PemReader(keyReader))
        {
            logger.error("========인증키 파일 읽어오기 s============" + keyPath);

            {
                PemObject pemObject = pemReader.readPemObject();
                content = pemObject.getContent();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        logger.error("========인증키 파일 읽어오기 e============" + keyPath);
        // 인증키 파일 읽어오기 e

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(content);
        KeyFactory kf = KeyFactory.getInstance("EC");

        try {
            //ECPrivateKeyImpl 인식 불가능.
            //ECPrivateKey ecPrivateKey = new ECPrivateKeyImpl(readPrivateKey(keyPath));
            ECPrivateKey ecPrivateKey = (ECPrivateKey) kf.generatePrivate(spec);
            JWSSigner jwsSigner = new ECDSASigner(ecPrivateKey.getS());
            jwt.sign(jwsSigner);

        } catch (JOSEException e) {
            e.printStackTrace();
        }

        client_secret = jwt.serialize();

        //--- 2. 토큰 검증 및 사용자 정보 발급한다.
        String reqUrl = "https://appleid.apple.com" + "/auth/token";

        Map<String, String> tokenRequest = new HashMap<>();
        tokenRequest.put("client_id", clientId);
        tokenRequest.put("client_secret", client_secret);
        tokenRequest.put("code", code);
        tokenRequest.put("grant_type", "authorization_code");

        logger.error("========applecallback client_id============" + clientId);
        logger.error("========applecallback client_secret============" + client_secret);
        logger.error("========applecallback code============" + code); //5분 동안 유효한 일회용 인증 코드
        logger.error("========applecallback reqUrl============" + reqUrl);

        String apiResponse = doPost(reqUrl, tokenRequest);

        // id_token decode s
        // id_token을 통해 사용자의 식별 정보가 포함 된 JSON 웹 토큰 받기(JWT)
        JSONObject tokenResponse = new JSONObject(apiResponse);
        SignedJWT signedJWT = SignedJWT.parse(tokenResponse.getString("id_token"));
        ReadOnlyJWTClaimsSet getPayload = signedJWT.getJWTClaimsSet();
        String payload = getPayload.toJSONObject().toJSONString();
        JSONObject appleInfo = new JSONObject(payload);
        // id_token decode e

        logger.error("========applecallback appleInfo============" + appleInfo);

        // GSON
        Gson gson = new Gson();
        HashMap resEntity = gson.fromJson(appleInfo.toString(), HashMap.class);

        String id ="";
        String email = "";

        id = String.valueOf(resEntity.get("sub")); //고유값
        email = String.valueOf(resEntity.get("email"));
        String[] name = email.split("\\@"); //이메일 @ 앞자리

        logger.debug("appleInfo.body = id{} ", id);
        logger.debug("appleInfo.body = name{} ", name[0]);
        logger.debug("appleInfo.body = email{} ", email);

        //SNS 로그인 처리 시 이력이 있으면 로그인처리 없으면 회원정보 테이블에 비회원으로 정보를 생성한다.
        model.addAttribute("user_name", name[0]);
        model.addAttribute("email", email);
        model.addAttribute("user_type", "비회원");
        model.addAttribute("sns_type", "apple");

        // 회원가입 처리 (생략)

        return "/applelogin_complete";
    }

    public static String doPost(String url, Map<String, String> param) {

        String result = null;
        CloseableHttpClient httpclient = null;
        CloseableHttpResponse response = null;
        Integer statusCode = null;
        String reasonPhrase = null;

        try {
            httpclient = HttpClients.createDefault();
            HttpPost httpPost = new HttpPost(url);
            httpPost.addHeader("Content-Type", "application/x-www-form-urlencoded");
            List<NameValuePair> nvps = new ArrayList<>();
            //Set<Map.Entry<String, String>> entrySet = param.entrySet();
            //for (Map.Entry<String, String> entry : entrySet) {
            Set<Map.Entry<String, String>> entrySet = param.entrySet();
            for (Map.Entry<String, String> entry : entrySet) {
                String fieldName = entry.getKey();
                String fieldValue = entry.getValue();
                //nvps.addAll((Collection<? extends NameValuePair>) new BasicNameValuePair(fieldName, fieldValue));
                nvps.add(new BasicNameValuePair(fieldName, fieldValue));
            }
            UrlEncodedFormEntity formEntity = new UrlEncodedFormEntity(nvps);
            httpPost.setEntity(formEntity);
            response = httpclient.execute(httpPost);
            statusCode = response.getStatusLine().getStatusCode();
            reasonPhrase = response.getStatusLine().getReasonPhrase();
            org.apache.http.HttpEntity entity = response.getEntity();
            result = EntityUtils.toString(entity, "UTF-8");

            if (statusCode != 200) {
                logger.error(String.format("[doPost]post url(%s) failed. status code:%s. reason:%s. param:%s. result:%s", url, statusCode, reasonPhrase, objectMapper.writeValueAsString(param), result));
            }
            EntityUtils.consume(entity);
        } catch (Throwable t) {
            try {
                logger.error(String.format("[doPost]post url(%s) failed. status code:%s. reason:%s. param:%s.", url, statusCode, reasonPhrase, objectMapper.writeValueAsString(param)), t);
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        } finally {
            try {
                if (response != null) {
                    response.close();
                }
                if (httpclient != null) {
                    httpclient.close();
                }
            } catch (IOException e) {
                try {
                    logger.error(String.format("[doPost]release http post resource failed. url(%s). reason:%s, param:%s.", url, e.getMessage(), objectMapper.writeValueAsString(param)));
                } catch (IOException e1) {
                    // TODO Auto-generated catch block
                    e1.printStackTrace();
                }
            }
        }
        return result;
    }
}