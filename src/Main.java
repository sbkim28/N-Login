import com.ignited.login.LoginFailException;
import com.ignited.login.NaverLogin;
import com.ignited.login.WrongCaptchaException;
import com.ignited.login.WrongIdPasswordException;
import org.jsoup.Jsoup;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Map;

public class Main {

    public static final int MAX_ATTEMPT = 5;

    // example
    public static void main(String[] args){
        int attempt = 0;
        Map<String, String> loginCookies = null;
        NaverLogin login;
        while (true) {
            try {
                BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
                System.out.println("NAVER LOGIN");
                System.out.print("YOUR ID : ");
                String id = br.readLine();
                System.out.print("YOUR PASSWORD : ");
                String password = br.readLine();
                login =  new NaverLogin(id, password);

                boolean v = login.login();
                if (!v) {
                    System.out.print("Captcha - ");
                    System.out.println(login.getChptchaURL());
                    String chptcha = br.readLine();
                    login.login(chptcha);
                }

                loginCookies = login.getLoginCookies();
                break;
            } catch (WrongIdPasswordException | WrongCaptchaException e) {
                login = null;
                ++attempt;
                System.err.println("LOGIN FAILED : ");
                e.printStackTrace();
                System.err.println("LEFT ATTEMPT : " + (MAX_ATTEMPT - attempt));
                if(attempt >= MAX_ATTEMPT){
                    System.err.println("You've exceeded the number of allowed attempts.");
                    break;
                }
                try {
                    Thread.sleep(500);
                } catch (InterruptedException e1) {
                    e1.printStackTrace();
                }
            } catch (LoginFailException | IOException e) {
                login = null;
                System.err.println("LOGIN FAILED : ");
                e.printStackTrace();
                break;
            }
        }
        if(loginCookies == null) return;

        System.out.println("LOGOUT : " + login.logout());
    }
}
