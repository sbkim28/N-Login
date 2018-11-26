package com.ignited.login;

import com.google.gson.ExclusionStrategy;
import com.google.gson.FieldAttributes;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.JsonAdapter;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;

import java.io.*;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class NaverLogin {

    private static final String CAPTCHA = "https://nid.naver.com/login/image/captcha/nhncaptchav4.gif?1&key=";

    private static final String KEYS = "https://nid.naver.com/login/ext/keys.nhn";
    private static final String LOGIN = "https://nid.naver.com/nidlogin.login";
    private static final String LOGOUT = "https://nid.naver.com/nidlogin.logout";

    private String id;
    private String password;

    private String chptchakey;
    private boolean onCaptcha;

    private Map<String, String> loginCookies;

    public NaverLogin(String id, String password) {
        this.id = id;
        this.password = password;
    }

    public boolean logout(){
        int res;
        try {
            res = Jsoup.connect(LOGOUT)
                    .cookies(loginCookies)
                    .execute()
                    .statusCode();
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
        if(res == 200){
            loginCookies = null;
            return true;
        }else {
            return false;
        }
    }

    public boolean login() throws LoginFailException {
        return login(null);
    }

    public boolean login(String captcha) throws LoginFailException {

        RSAModule module = new RSAModule();
        String encnm;
        String encpw;
        try {
            String[] keys = getKeys();
            encnm = keys[1];
            module.setPublic(keys[2], keys[3]);
            String enc = getValueWithLength(keys[0]) + getValueWithLength(id) + getValueWithLength(password);
            encpw = module.encrypt(enc);
        } catch (IOException | GeneralSecurityException e) {
           throw new LoginFailException(e);
        }

        Map<String, String> data = new HashMap<>();
        data.put("enctp", "1");
        data.put("encpw", encpw);
        data.put("encnm", encnm);
        data.put("svctype", "0");
        data.put("viewtype", "0");
        data.put("locale","ko_KR");
        data.put("smart_LEVEL", "-1");
        data.put("url", "http://www.naver.com");
        data.put("nvlong","on");

        if(onCaptcha){
            data.put("chptcha", captcha);
            data.put("chptchakey", chptchakey);
            data.put("captcha_type", "image");
        }

        Document body;
        Connection.Response res;
        try {
             res = Jsoup.connect(LOGIN)
                    .header("Referer", LOGIN)
                    .data(data)
                    .method(Connection.Method.POST)
                    .execute();

            body = res.parse();
        } catch (IOException e) {
            throw new LoginFailException(e);
        }

        Elements chptchakeys;
        if((chptchakeys = body.select("#chptchakey")).size() == 1){
            if (onCaptcha) throw new WrongCaptchaException(captcha);
            onCaptcha = true;
            chptchakey = chptchakeys.first().val();
            return false;
        }
        onCaptcha = false;
        String strBody = body.toString();
        Pattern p = Pattern.compile("location.replace\\(\"(.*?)\"\\)");
        Matcher m = p.matcher(strBody);
        if(m.find()){
            String redirect = m.group(0);
            redirect = redirect.substring(redirect.indexOf("\"") + 1, redirect.lastIndexOf("\""));

            try {
                loginCookies = Jsoup.connect(redirect).execute().cookies();
            } catch (IOException e) {
                throw new LoginFailException(e);
            }
        }else {
            throw new WrongIdPasswordException("Wrong id or Password.\n" + "ID : \"" + id + "\", Password : \"" + password + "\"");
        }
        return true;
    }

    public boolean isLogin(){
        return loginCookies != null;
    }

    public String getChptchaURL() {
        return CAPTCHA + chptchakey;
    }

    public boolean isOnCaptcha() {
        return onCaptcha;
    }

    private String getValueWithLength(String str){
        return ((char) str.length()) + str;
    }


    private String[] getKeys() throws IOException {
        return Jsoup.connect(KEYS).get().text().split(",");
    }

    public Map<String, String> getLoginCookies() {
        return loginCookies;
    }

    public boolean write(String path){
        if(!isLogin()) throw new IllegalStateException("Not Login");
        File file = new File(path);
        try(FileWriter writer = new FileWriter(file)) {
            new GsonBuilder().setExclusionStrategies(new ExclusionStrategy() {
                @Override
                public boolean shouldSkipField(FieldAttributes field) {
                    return field.getName().equals("chptchakey")
                            || field.getName().equals("onCaptcha");
                }

                @Override
                public boolean shouldSkipClass(Class<?> aClass) {
                    return false;
                }
            }).create().toJson(this, writer);

        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }

        return true;
    }

    public static NaverLogin read(String path) throws IOException {
        File file = new File(path);
        try (FileReader writer = new FileReader(file)){
            return new Gson().fromJson(writer, NaverLogin.class);
        }
    }
}
